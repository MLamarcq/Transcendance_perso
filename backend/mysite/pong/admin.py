from django.contrib import admin
from .models import User, Tournament, Party

admin.site.register(User)
admin.site.register(Tournament)
admin.site.register(Party)

# Register your models here.
