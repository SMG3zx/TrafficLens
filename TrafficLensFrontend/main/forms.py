from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.forms import ModelForm
from .models import PcapFile

_PCAP_MAGIC = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x0a\x0d\x0d\x0a'}
_MAX_UPLOAD_MB = 50

# uncomment this if you want to change the class/design of the login form
class UserLoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ['username', 'password']


# Customizing Registration Form from UserCreationForm
class UserRegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'password1', 'password2']


class ResetPasswordForm(PasswordResetForm):
    class Meta:
        model = User
        fields = ['email']


class ResetPasswordConfirmForm(SetPasswordForm):
    class Meta:
        model = User
        fields = ['new_password1', 'new_password2']


class PcapUploadForm(ModelForm):
    class Meta:
        model = PcapFile
        fields = ['file']

    def clean_file(self):
        f = self.cleaned_data.get('file')
        if not f:
            return f
        if f.size > _MAX_UPLOAD_MB * 1024 * 1024:
            raise ValidationError(f"File too large. Maximum size is {_MAX_UPLOAD_MB} MB.")
        magic = f.read(4)
        f.seek(0)
        if magic not in _PCAP_MAGIC:
            raise ValidationError("Invalid file. Please upload a valid PCAP (.pcap or .pcapng) file.")
        return f