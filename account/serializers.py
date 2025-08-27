from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers
from .models import MyUser
from .utils import Utils


class MyUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = MyUser
        fields = [
            "email",
            "name",
            "password",
            "password2",
            "tc",
            "created_at",
            "updated_at"
        ]
        read_only_fields = [
            "created_at",
            "updated_at"
        ]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError({"password": "Passwords must match"})
        attrs.pop("password2", None)  # don't pass to model/manager
        return attrs

    def create(self, value):
        return MyUser.objects.create_user(
            email=value["email"],
            name=value["name"],
            tc=value.get("tc", False),
            password=value["password"],
        )

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = MyUser
        fields = [
            "email",
            "password",
        ]

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = [
            "id",
            "email",
            "name",
        ]

class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, write_only=True, style={"input_type": "password"}
    )
    password2 = serializers.CharField(
        max_length=255, write_only=True, style={"input_type": "password"}
    )

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "Passwords must match"})
        return attrs

class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = MyUser
        fields = ["email"]

    def validate(self, attrs):
        email = attrs["email"]
        try:
            user = MyUser.objects.get(email=email)
        except MyUser.DoesNotExist:
            raise serializers.ValidationError({"email": "Email not registered"})

        uid = urlsafe_base64_encode(force_bytes(user.pk))  # no .decode()
        token = PasswordResetTokenGenerator().make_token(user)
        # stash for the view
        attrs["reset_link"] = f"http://127.0.0.1:3000/reset/{uid}/{token}"
        return attrs

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, max_length=255, style={"input_type": "password"})
    password2 = serializers.CharField(write_only=True, max_length=255, style={"input_type": "password"})

    def validate(self, attrs):
        uuid = self.context.get("uuid")
        token  = self.context.get("token")
        if not uuid or not token:
            raise serializers.ValidationError({"detail": "Invalid reset link"})

        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "Passwords must match"})

        try:
            uid = smart_str(urlsafe_base64_decode(uuid))
            user = MyUser.objects.get(pk=uid)
        except (MyUser.DoesNotExist, DjangoUnicodeDecodeError, ValueError, TypeError):
            raise serializers.ValidationError({"detail": "Invalid reset link"})

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"detail": "Token invalid or expired"})

        self.context["user"] = user
        return attrs
