import struct
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from main.models import PcapFile


def _minimal_pcap() -> bytes:
    magic = b"\xd4\xc3\xb2\xa1"
    return magic + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)


# ── Homepage ──────────────────────────────────────────────────────────────────

class HomepageViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="tester", password="pass123!")

    def test_redirect_when_not_logged_in(self):
        response = self.client.get(reverse("homepage"))
        self.assertRedirects(response, "/login/")

    def test_homepage_loads_when_logged_in(self):
        self.client.login(username="tester", password="pass123!")
        response = self.client.get(reverse("homepage"))
        self.assertEqual(response.status_code, 200)

    def test_upload_rejects_non_pcap(self):
        self.client.login(username="tester", password="pass123!")
        fake = SimpleUploadedFile("evil.pcap", b"this is not a pcap file")
        self.client.post(reverse("homepage"), {"file": fake})
        self.assertEqual(PcapFile.objects.filter(user=self.user).count(), 0)

    def test_upload_accepts_valid_pcap(self):
        self.client.login(username="tester", password="pass123!")
        valid = SimpleUploadedFile("capture.pcap", _minimal_pcap())
        self.client.post(reverse("homepage"), {"file": valid})
        self.assertEqual(PcapFile.objects.filter(user=self.user).count(), 1)


# ── Register ──────────────────────────────────────────────────────────────────

class RegisterViewTests(TestCase):
    def test_get_returns_form(self):
        response = self.client.get(reverse("register"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create account")

    @patch("main.views.EmailMessage")
    def test_register_creates_inactive_user(self, mock_email_cls: MagicMock):
        mock_email_cls.return_value.send.return_value = None
        self.client.post(
            reverse("register"),
            {
                "first_name": "Test",
                "last_name": "User",
                "username": "newuser",
                "email": "test@example.com",
                "password1": "Str0ng!Pass#99",
                "password2": "Str0ng!Pass#99",
            },
        )
        user = User.objects.get(username="newuser")
        self.assertFalse(user.is_active)

    @patch("main.views.EmailMessage")
    def test_register_redirects_to_login(self, mock_email_cls: MagicMock):
        mock_email_cls.return_value.send.return_value = None
        response = self.client.post(
            reverse("register"),
            {
                "first_name": "Test",
                "last_name": "User",
                "username": "newuser2",
                "email": "test2@example.com",
                "password1": "Str0ng!Pass#99",
                "password2": "Str0ng!Pass#99",
            },
        )
        self.assertRedirects(response, reverse("login"))


# ── Delete PCAP ───────────────────────────────────────────────────────────────

class DeletePcapTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="tester", password="pass123!")

    def _make_upload(self, user: User) -> PcapFile:
        return PcapFile.objects.create(
            user=user,
            file=ContentFile(_minimal_pcap(), name="test.pcap"),
        )

    def test_delete_requires_login(self):
        upload = self._make_upload(self.user)
        response = self.client.post(reverse("delete_pcap", args=[upload.id]))
        self.assertIn("/login/", response["Location"])

    def test_delete_own_upload(self):
        self.client.login(username="tester", password="pass123!")
        upload = self._make_upload(self.user)
        response = self.client.post(reverse("delete_pcap", args=[upload.id]))
        self.assertRedirects(response, reverse("homepage"))
        self.assertFalse(PcapFile.objects.filter(id=upload.id).exists())

    def test_cannot_delete_other_users_upload(self):
        other = User.objects.create_user(username="other", password="pass123!")
        upload = self._make_upload(other)
        self.client.login(username="tester", password="pass123!")
        response = self.client.post(reverse("delete_pcap", args=[upload.id]))
        self.assertEqual(response.status_code, 404)
        self.assertTrue(PcapFile.objects.filter(id=upload.id).exists())
