from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.forms import FileField, CharField
from django.forms.forms import Form
from django.forms.models import ModelForm


class UploadFileForm(Form):
    file = FileField()


class RegisterModelFrom(ModelForm):
    confirm_password = CharField(max_length=255, label="Confirm password")

    class Meta:
        model = User
        fields = "username", "password", "confirm_password"

    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data


class LoginModelForm(Form):
    username = forms.CharField(max_length=25)
    password = forms.CharField(max_length=255)

    def get_user(self):
        return self._cache_user

    def clean(self):
        cleaned_data = super().clean()

        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if not username or not password:
            raise ValidationError("Имя пользователя и пароль не могут быть пустыми")

        user = authenticate(username=username, password=password)

        if user is None:
            raise ValidationError("Пользователь с таким именем или паролем не найден")

        self._cache_user = user
        return cleaned_data
