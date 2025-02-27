import logging
from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_save, post_delete
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils.timezone import now
from django.contrib.auth import get_user_model
from .models import AuditLog
from django.dispatch import Signal
from accounts.models import CustomUser

User = get_user_model()

user_action_signal = Signal()


def get_client_ip(request):
    if not request:
        return None
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]  # Agar bir nechta IP bo'lsa, birinchisini olish
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@receiver(post_save, sender=User)
def log_user_save(sender, instance, created, **kwargs):
    action = f"user {instance.username} created" if created else "user updated"
    ip_address = getattr(instance, "temp_ip", None)
    AuditLog.create_log(user=instance, action=action, ip_address=ip_address)


@receiver(post_delete, sender=User)
def log_user_delete(sender, instance, **kwargs):
    try:
        AuditLog.create_log(user=None, action=f"user {instance.username} deleted")

    except Exception as e:
        print(f"Error: {e}")


logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ip_address = get_client_ip(request)  # IP manzil olish
    user_agent = request.META.get("HTTP_USER_AGENT", "")

    # Log yozish
    AuditLog.create_log(user=user, action="User logged in", ip_address=ip_address, user_agent=user_agent)
    logger.info(f"LOGIN: {user} logged in from {ip_address}")
