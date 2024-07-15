from django.urls import path, include
#from two_factor.urls import urlpatterns as tf_urls

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("signup", views.signup, name ="signup"),
    path("signin", views.signin, name="signin"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("statistics/", views.statistics, name="statistics"),
    path("chat/", views.chat_solo, name="chat_solo"),
    path("chat/<chat_name>", views.chat_room, name="chat_room"),
    path("otp/", views.otp_view, name="otp"),
    path("profile", views.profile_view, name = "profile"),
    path("add_friends", views.add_friends, name ="add_friends"),
    path("delete_friends", views.delete_friends, name = "delete_friends"),
    path("add_chat", views.add_chat, name="add_chat"),
    path("join_chat", views.join_chat, name="join_chat")
]