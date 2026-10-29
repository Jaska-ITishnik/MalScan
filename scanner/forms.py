from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.forms import FileField, CharField
from django.forms.forms import Form
from django.forms.models import ModelForm


class UploadFileForm(Form):
    file = FileField(label="Fayl", error_messages={"required": "Tahlil qilish uchun fayl tanlang."})


class RegisterModelFrom(ModelForm):
    username = forms.CharField(max_length=150, label="Foydalanuvchi nomi")
    password = CharField(widget=forms.PasswordInput, label="Parol")
    confirm_password = CharField(max_length=255, widget=forms.PasswordInput, label="Parolni qayta kiriting")

    class Meta:
        model = User
        fields = "username", "password", "confirm_password"

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data["username"]
        if User.objects.filter(username=username).exists():
            raise ValidationError("Bu foydalanuvchi nomi band. Boshqa nom tanlang.")
        cleaned_data["password"] = make_password(cleaned_data["password"])
        return cleaned_data


class LoginModelForm(Form):
    username = forms.CharField(max_length=25, label="Login yoki elektron pochta")
    password = forms.CharField(max_length=255, widget=forms.PasswordInput, label="Parol")

    def get_user(self):
        return self._cache_user

    def clean(self):
        cleaned_data = super().clean()

        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if not username or not password:
            raise ValidationError("Login va parolni kiriting.")

        user = authenticate(username=username, password=password)

        if user is None:
            raise ValidationError("Login yoki parol noto‘g‘ri.")

        self._cache_user = user
        return cleaned_data
