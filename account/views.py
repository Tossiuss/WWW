from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.parsers import FileUploadParser
from rest_framework.authtoken.models import Token
from .permissions import IsActivePermission
from rest_framework import status
from .serializers import (
    RegistrationSerializer, 
    ActivationSerializer, 
    LoginSerializer, 
    ChangePasswordSerializer, 
    DeleteAccountSerializer,
    AdminDeleteUserSerializer,
)
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate


User = get_user_model()


class RegistrationView(CreateAPIView):
    serializer_class = RegistrationSerializer


class ActivationView(CreateAPIView):
    serializer_class = ActivationSerializer


class LoginView(ObtainAuthToken):
    serializer_class = LoginSerializer


class LogoutView(APIView):
    permission_classes = [IsActivePermission]

    def post(self, request):
        user = request.user
        Token.objects.filter(user=user).delete()
        return Response(
            'Вы успешно вышли из своего аккаунта'
        )


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.set_new_password()
        return Response(
            'Пароль успешно обнавлен', status=200
        )


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = DeleteAccountSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, username=email, password=password)
            if user is not None:
                user.delete()
                return Response({'message': 'Аккаунт успешно удален'}, status=status.HTTP_204_NO_CONTENT)
            else:
                return Response({'message': 'Неверные почта и/или пароль'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class AdminDeleteUserView(APIView):
    permission_classes = [IsAdminUser]
    authentication_classes = [SessionAuthentication] 

    def post(self, request):
        serializer = AdminDeleteUserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                user.delete()
                return Response({'message': f'Пользователь с email {email} успешно удален'}, status=status.HTTP_204_NO_CONTENT)
            except User.DoesNotExist:
                return Response({'message': 'Пользователь с указанным email не найден'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AvatarUploadView(APIView):
    parser_class = (FileUploadParser,)

    def put(self, request, format=None):
        avatar = request.data.get('avatar')
        if not avatar:
            return Response({'error': 'Фото не передано'}, status=status.HTTP_400_BAD_REQUEST)

        request.user.avatar = avatar
        request.user.save()
        return Response({'message': 'Фото профиля обновлено'}, status=status.HTTP_200_OK)
    
