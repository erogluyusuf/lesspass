from datetime import timedelta
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from api.models import PairingSession

SESSION_TTL_SECONDS = 120


class CreatePairingSessionSerializer(serializers.Serializer):
    requester_public_key = serializers.RegexField(
        regex=r"^[0-9a-fA-F]{64,260}$",
        required=True,
    )


class ApprovePairingSessionSerializer(serializers.Serializer):
    sender_public_key = serializers.RegexField(
        regex=r"^[0-9a-fA-F]{64,260}$",
        required=True,
    )
    iv = serializers.RegexField(regex=r"^[0-9a-fA-F]{24}$", required=True)
    ciphertext = serializers.RegexField(regex=r"^[0-9a-fA-F]+$", required=True)


class PairingSessionCreateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CreatePairingSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Opportunistic cleanup of expired sessions
        PairingSession.objects.filter(expires_at__lt=timezone.now()).delete()

        session = PairingSession.objects.create(
            requester_public_key=serializer.validated_data["requester_public_key"],
            expires_at=timezone.now() + timedelta(seconds=SESSION_TTL_SECONDS),
        )
        return Response(
            {
                "session_id": str(session.id),
                "requester_public_key": session.requester_public_key,
                "expires_at": session.expires_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class PairingSessionApproveView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, session_id):
        try:
            session = PairingSession.objects.get(id=session_id)
        except PairingSession.DoesNotExist:
            return Response(
                {"detail": "Pairing session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if session.expires_at < timezone.now():
            session.delete()
            return Response(
                {"detail": "Pairing session expired."},
                status=status.HTTP_410_GONE,
            )

        if session.is_approved:
            return Response(
                {"detail": "Pairing session already approved."},
                status=status.HTTP_409_CONFLICT,
            )

        serializer = ApprovePairingSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        session.sender_public_key = serializer.validated_data["sender_public_key"]
        session.wrapped_token_iv = serializer.validated_data["iv"]
        session.wrapped_token_ciphertext = serializer.validated_data["ciphertext"]
        session.is_approved = True
        session.save(
            update_fields=[
                "sender_public_key",
                "wrapped_token_iv",
                "wrapped_token_ciphertext",
                "is_approved",
            ]
        )

        return Response({"status": "approved"}, status=status.HTTP_200_OK)


class PairingSessionPollView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, session_id):
        try:
            session = PairingSession.objects.get(id=session_id)
        except PairingSession.DoesNotExist:
            return Response(
                {"detail": "Pairing session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if session.expires_at < timezone.now():
            session.delete()
            return Response(
                {"detail": "Pairing session expired."},
                status=status.HTTP_410_GONE,
            )

        if not session.is_approved:
            return Response(
                {"status": "pending", "requester_public_key": session.requester_public_key},
                status=status.HTTP_200_OK,
            )

        payload = {
            "status": "approved",
            "senderPublicKeyHex": session.sender_public_key,
            "wrappedMasterToken": {
                "iv": session.wrapped_token_iv,
                "ciphertext": session.wrapped_token_ciphertext,
            },
        }
        # Burn-after-reading: destroy encrypted payload immediately after delivery
        session.delete()
        return Response(payload, status=status.HTTP_200_OK)
