from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError


class UploadFileForm(forms.Form):
    file = forms.FileField()


class LoginModelForm(forms.Form):
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
