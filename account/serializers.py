from rest_framework import serializers
from .models import MyUser

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

"""class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ("email",)

    def validate(self, attrs):
        email = attrs["email"]
        if MyUser.objects.filter(email=email).exists():
            user = MyUser.objects.get(email=email)
        else:
            raise serializers.ValidationError({"email": "Email not registered"})"""

