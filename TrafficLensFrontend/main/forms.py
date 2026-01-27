from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from .models import PcapFile

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