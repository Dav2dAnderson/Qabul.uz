from django.shortcuts import render

from rest_framework import generics, permissions, exceptions, status
# from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from audit.signals import get_client_ip
from audit.models import AuditLog
from .models import CustomUser, Branch, City
from .serializers import CustomUserSerializer, CustomUserRetrieveSerializer, BranchSerializer, CitySerializer
# Create your views here.


class UserRegistrationView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.AllowAny, ]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  # Foydalanuvchi yaratildi

        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if ip_address:
            user.temp_ip = ip_address
            user.temp_user = user_agent
            AuditLog.objects.create(user=user, action="User registered", ip_address=ip_address, user_agent=user_agent)

        return Response(
            {'message': "Foydalanuvchi muvaffaqiyatli ro'yxatdan o'tdi.", "user": serializer.data},
            status=status.HTTP_201_CREATED
        )


class UserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.IsAdminUser, permissions.IsAuthenticated]


class UserProfileView(generics.RetrieveAPIView, generics.UpdateAPIView):
    serializer_class = CustomUserRetrieveSerializer
    permission_classes = [permissions.IsAuthenticated, ]

    def get_object(self):
        user = self.request.user
        if not user.is_authenticated:
            raise exceptions.AuthenticationFailed("Foydalanuvchi autenfikatsiyadan qilinmagan.")
        return user


class BranchAPIView(generics.ListCreateAPIView):
    queryset = Branch.objects.all()
    serializer_class = BranchSerializer
    permission_classes = [permissions.IsAdminUser]
    

class CityAPIView(generics.ListCreateAPIView):
    queryset = City.objects.all()
    serializer_class = CitySerializer
    permission_classes = [permissions.IsAdminUser]





