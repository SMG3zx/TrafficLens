# import this to require login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

# import this for sending email to user
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from main.forms import UserRegistrationForm, PcapUploadForm
from trafficlens_core import analyze_pcap_bytes
from .models import PcapFile

# Create your views here.

@login_required(login_url='login')
def homepage(request):
    user = request.user
    uploads = PcapFile.objects.filter(user=user).order_by('-uploaded_at')

    if request.method == 'POST':
        form = PcapUploadForm(request.POST, request.FILES)
        if form.is_valid():
            upload = form.save(commit=False)
            upload.user = user
            upload.save()
            messages.success(request, "PCAP uploaded successfully.")
            return redirect('homepage')
        else:
            messages.error(request, "Upload failed. Please try again.")
    else:
        form = PcapUploadForm()

    return render(request, 'homepage.html', {
        'form': form,
        'uploads': uploads,
    })


def register(request):
    form = UserRegistrationForm()

    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            # email user with activation link
            current_site = get_current_site(request)
            mail_subject = "Activate your account."

            # the message will render what is written in main/email_activation/activate_email_message.html
            message = render_to_string('main/email_activation/activate_email_message.html', {
                    'user': form.cleaned_data['username'],
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token':  default_token_generator.make_token(user),
                })
            to_email = form.cleaned_data['email']
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            messages.success(request, 'Account created successfully. Please check your email to activate your account.')
            return redirect('login')
        else:
            messages.error(request, 'Account creation failed. Please try again.')


    return render(request, 'main/register.html',{
        'form': form
    })

# to activate user from email
def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'main/email_activation/activation_successful.html')
    else:
        return render(request, 'main/email_activation/activation_unsuccessful.html')

@login_required(login_url='login')
def analysis(request, pcap_id):
    upload = get_object_or_404(PcapFile, id=pcap_id, user=request.user)

    packets_rows = []
    error = None

    try:
        with upload.file.open("rb") as pcap_file:
            packets_rows = analyze_pcap_bytes(pcap_file.read())
    except ValueError as exc:
        error = str(exc)

    paginator = Paginator(packets_rows, 200)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(request, "analysis.html", {
        "upload": upload,
        "page_obj": page_obj,
        "error": error,
    })
