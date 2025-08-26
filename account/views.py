from django.contrib.auth import authenticate
from django.core.serializers import serialize
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import MyUserSerializer, UserLoginSerializer, UserProfileSerializer, ChangePasswordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import AuthenticationFailed

def get_tokens_for_user(user):
    if not user.is_active:
      raise AuthenticationFailed("User is not active")

    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterApiView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        serializer = MyUserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Login success'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginApiView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        user = authenticate(request=request, email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token':token, "detail": "login Success"}, status=status.HTTP_200_OK)
        return Response(
            {"non_field_errors": ["Email or password not valid"]},
            status=status.HTTP_401_UNAUTHORIZED,
        )

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = UserProfileSerializer(instance=request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"user": request.user})
        serializer.is_valid(raise_exception=True)
        new_pss = serializer.validated_data["password"]

        user = request.user
        user.set_password(new_pss)
        user.save(update_fields=["password"])
        user.refresh_from_db()

        if not user.check_password(new_pss):
            return Response({"detail": "Password update failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"detail": "Password updated"}, status=status.HTTP_200_OK)

"""class SendPasswordResetEmailApiView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({"msg": "Reset password send your email. please checked your email please."},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)"""
