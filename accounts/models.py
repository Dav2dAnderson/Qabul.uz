from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.text import slugify
# Create your models here.


class City(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=150, null=True, blank=True, unique=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        return super().save(*args, **kwargs)


class Branch(models.Model):
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=200, null=True, blank=True, unique=True)
    city = models.ForeignKey(City, on_delete=models.PROTECT)
    opened_date = models.DateField()


    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        return super().save(*args, **kwargs)


class CustomUser(AbstractUser):
    SUPER_ADMIN = "super_admin"
    BANK_OPERATOR = "bank_operator"
    GOVERNMENT_OFFICER = "government_officer"
    BRANCH_ADMIN = "branch_admin"

    ROLE_CHOICES = (
        (SUPER_ADMIN, "Super Admin"),
        (BANK_OPERATOR, "Bank Operator"),
        (GOVERNMENT_OFFICER, "Davlat Xodimi"),
        (BRANCH_ADMIN, "Filial Admin"),
    )

    phone_number = models.CharField(max_length=20, unique=True, verbose_name="Telefon raqam")
    city = models.CharField(max_length=150, verbose_name="Hudud")
    birth_date = models.DateField(verbose_name="Tug'ilgan sana")
    is_paid = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=GOVERNMENT_OFFICER)
    branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True)
    temp_ip = None
    temp_agent = None

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name', 'city', 'birth_date']

    def __str__(self):
        return self.username

