from datetime import timedelta
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from api.models import PairingSession


class ZeroKnowledgePairingRelayTests(APITestCase):
    def setUp(self):
        self.requester_pub = "04" + "a1" * 64
        self.sender_pub = "04" + "b2" * 64
        self.sample_iv = "c3" * 12
        self.sample_cipher = "d4" * 48

    def test_full_pairing_lifecycle_and_burn_after_reading(self):
        # 1. New device opens anonymous relay session
        create_res = self.client.post(
            reverse("pairing-create"),
            {"requester_public_key": self.requester_pub},
            format="json",
        )
        self.assertEqual(create_res.status_code, status.HTTP_201_CREATED)
        session_id = create_res.data["session_id"]

        # 2. Poll before approval returns pending
        poll_pending = self.client.get(reverse("pairing-poll", args=[session_id]))
        self.assertEqual(poll_pending.status_code, status.HTTP_200_OK)
        self.assertEqual(poll_pending.data["status"], "pending")

        # 3. Trusted device approves with ECDH-wrapped Master Token
        approve_res = self.client.post(
            reverse("pairing-approve", args=[session_id]),
            {
                "sender_public_key": self.sender_pub,
                "iv": self.sample_iv,
                "ciphertext": self.sample_cipher,
            },
            format="json",
        )
        self.assertEqual(approve_res.status_code, status.HTTP_200_OK)

        # 4. Second approval attempt is rejected (409 Conflict)
        replay_approve = self.client.post(
            reverse("pairing-approve", args=[session_id]),
            {
                "sender_public_key": self.sender_pub,
                "iv": self.sample_iv,
                "ciphertext": self.sample_cipher,
            },
            format="json",
        )
        self.assertEqual(replay_approve.status_code, status.HTTP_409_CONFLICT)

        # 5. New device fetches payload and verifies exact schema compatibility
        poll_approved = self.client.get(reverse("pairing-poll", args=[session_id]))
        self.assertEqual(poll_approved.status_code, status.HTTP_200_OK)
        self.assertEqual(poll_approved.data["status"], "approved")
        self.assertEqual(poll_approved.data["senderPublicKeyHex"], self.sender_pub)
        self.assertEqual(
            poll_approved.data["wrappedMasterToken"]["ciphertext"], self.sample_cipher
        )

        # 6. Burn-after-reading: subsequent read returns 404 Not Found
        second_read = self.client.get(reverse("pairing-poll", args=[session_id]))
        self.assertEqual(second_read.status_code, status.HTTP_404_NOT_FOUND)

    def test_expired_session_is_rejected_and_purged(self):
        session = PairingSession.objects.create(
            requester_public_key=self.requester_pub,
            expires_at=timezone.now() - timedelta(seconds=5),
        )
        res = self.client.get(reverse("pairing-poll", args=[str(session.id)]))
        self.assertEqual(res.status_code, status.HTTP_410_GONE)
        self.assertFalse(PairingSession.objects.filter(id=session.id).exists())
