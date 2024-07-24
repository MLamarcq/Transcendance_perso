from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect
from base64 import b64encode
from django.core.files.base import ContentFile
from .utils import get_friends #, CustomPasswordChangeForm
from .models import NewUser, Tournament, Party, Chat, Message, Statistic, Participant, Friendship, BlockedUser, send_message
from datetime import datetime
from django.db.models import Q
from django.db import IntegrityError
import pyotp
import qrcode
from io import BytesIO
import base64
import sys
import json
from django.http import JsonResponse
from datetime import timedelta
from django.contrib import messages
from django.template.loader import render_to_string
import logging
import re


logger = logging.getLogger('pong')

# def index(request):
	# if not request.user.is_authenticated:
	#     return HttpResponseRedirect(reverse("login"))
	# return (render(request, "pong/homepage.html"))

def index(request) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return (JsonResponse({'html' : html,                 
								'url' :   reverse("login")     
				}))
			return JsonResponse({'redirect' : reverse("login")})
		else :
			return HttpResponseRedirect(reverse("login"))
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/homepage_content.html", {}, request=request)
		return (JsonResponse({'html' : html,                 
							'url' :   reverse("index")     
				}))
	else :
		return render(request, "pong/homepage.html")

# def login_view(request):
	# if not request.user.is_authenticated:
	#     return render(request,"pong/login.html")
	# else:
	#     #ça serait bien de rajouter une notification "vous êtes déjà connecté"
	#     return HttpResponseRedirect(reverse("index"))

def login_view(request):
	if request.user.is_authenticated:
		message = "Vous êtes déjà connecté"
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/homepage_content.html", {'message': message}, request)
			return (JsonResponse({'html' : html,                 
							'url' :   reverse("index")     
				}))
		else:
			# Vous pouvez ajouter un message flash pour afficher la notification sur la page d'accueil.
			#messages.add_message(request, messages.INFO, message)
			return HttpResponseRedirect(reverse("index"))
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 
								'url' : reverse("login")
								})
		else:
			return render(request, "pong/login.html")



# def signup(request):
	# if request.user.is_authenticated:
	#     message = "Vous êtes déjà connecté"
	#     # if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#     #     return JsonResponse({'redirect': reverse("index"), 'message': message})
	#     # else:
	#         # Vous pouvez ajouter un message flash pour afficher la notification sur la page d'accueil.
	#     messages.add_message(request, messages.INFO, message)
	#     return HttpResponseRedirect(reverse("index"))
	# if request.method == "POST":
	#     email = request.POST.get("email")
	#     password = request.POST.get("password")
	#     confirm_password = request.POST.get("confirm_password")
	#     avatar = request.FILES.get("avatar")
	#     pseudo = request.POST.get("pseudo")

	#     if (confirm_password.casefold() != password.casefold()) :
	#         return render(request, 'pong/signup.html', {
	#             'error_message': "Password don't match, please try again."
	#         })
		
	#     if NewUser.objects.filter(pseudo=pseudo).exists():
	#         return render(request, 'pong/signup.html', {
	#             'error_message': "Username already exists. Please choose a different pseudo."
	#         })

		
	#     if NewUser.objects.filter(email=email).exists():
	#         return render(request, 'pong/signup.html', {
	#             'error_message': "Email already exists. Please choose a different email."
	#         })


	#     user = NewUser.objects.create_user(email=email, password=password, pseudo=pseudo, avatar=avatar)
	#     user.save()
	#     print(user.id)
	#     return HttpResponseRedirect(reverse("index"))
	# else:
	#     return render(request, "pong/signup.html")
		

def parsing_email(email) :
	if email :
		email = email.strip()
		try :
			index = email.index("@")
		except ValueError :
			logger.info("On passe ici exception")
			return ('')
		if ' ' in email :
			return ' '
		logger.info("oui oui")
		email_part = email[:index]
		domain_part = email[index+1:]
		logger.debug("email_part = %s", email_part)
		logger.debug("domain_part = %s", domain_part)
		if not email_part or '..' in email_part:
			return ''
		if not domain_part or '..' in domain_part:
			return ''
		if not (domain_part.endswith("com") or domain_part.endswith(".fr")) :
			return ('')
		email_invalid_chars = re.compile(r'[ !#\$%&\'\*\+\-/=\?\^_`\{\|\}~]')
		domain_invalid_chars = re.compile(r'[ !#\$%&\'\*\+\-/=\?\^_`\{\|\}~]')
		if email_invalid_chars.search(email_part) or domain_invalid_chars.search(domain_part):
			logger.info("Wrong char found !")
			return ''
	return (email)

def test_mail() :
	test_emails = [
		"example@'example.com",
		"example@example.fr",
		"example@ example.com",
		"example@example.c",
		"example@example.",
		" example@example.com ",
		"example@example..com",
		"example@example!.com"
	]

	for i,email in enumerate(test_emails):
		result = parsing_email(email)
		logger.debug("test n*%d retour fonction parsing = %s", i, result)


def validate_signup_data(email, password, confirm_password, pseudo):
	if not email :
		return "Email: this field can not be empty"
	if not password :
		return "Password: this field can not be empty"
	if not confirm_password :
		return "Confirm_password: this field can't be empty"
	if not pseudo:
		return "Pseudo: this field can't be empty"
	if confirm_password.casefold() != password.casefold():
		return "Password don't match, please try again."
	if NewUser.objects.filter(pseudo=pseudo).exists():
		return "Username already exists. Please choose a different pseudo."
	if NewUser.objects.filter(email=email).exists():
		return "Email already exists. Please choose a different email."
	return None


def signup(request):
	if request.user.is_authenticated:
		message = "Vous êtes déjà connecté"
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/homepage_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
								})
		else:
			#messages.add_message(request, messages.INFO, message)
			return HttpResponseRedirect(reverse("index"))

	if request.method == "POST":
		print("Nous passons bien ici oui")
		email = request.POST.get("email")
		password = request.POST.get("password")
		confirm_password = request.POST.get("confirm_password")
		avatar = request.FILES.get("avatar")
		pseudo = request.POST.get("pseudo")
		
		logger.debug("email avant parsing = %s", email)

		email = parsing_email(email)

		# test_mail()

		logger.debug("email apres parsing = %s", email)
		logger.debug("pseudo = %s", pseudo)
		logger.debug("password = %s", password)
		logger.debug("confirm_password = %s", confirm_password)


		error_message = validate_signup_data(email, password, confirm_password, pseudo)
		
		# logger.debug("error_message = %s", error_message)

		if error_message:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/signup_content.html", {'error_message': error_message}, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("signup")
				})
			else:
				return render(request, 'pong/signup.html', {'error_message': error_message})
		
		user = NewUser.objects.create_user(email=email, password=password, pseudo=pseudo, avatar=avatar)
		# user.create_statistic()
		user.save()
		
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))

	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			print("Nous passons bien ici 2")
			logger.info("html at ajax")
			html = render_to_string("pong/signup_content.html", {}, request=request)
			logger.debug("html in signup = %s", html)
			return JsonResponse({'html': html,
								'url' : reverse("signup")
			})
		else:
			return render(request, "pong/signup.html")



# def signin(request):
	# if request.user.is_authenticated:
	#     #ça serait bien de rajouter une notification "vous êtes déjà connecté"
	#     return HttpResponseRedirect(reverse("index"))
	# if request.method == "POST":
	#     email = request.POST.get("email")
	#     password = request.POST.get("password")
	#     user = authenticate(request, email=email, password=password)
	#     alerte = False
	#     if user is not None:
	#         # login(request, user)
	#         request.session['user_id'] = user.id
	#         if user.is_mfa_enabled is True:
	#             #send_otp(request)
	#             #request.session["email"] = email
	#             return redirect("otp")
	#         else:
	#             login(request, user)
	#             return HttpResponseRedirect(reverse("index"))
	#     else:
	#         alerte = True
	#         return render(request, "pong/signin.html", {
	#             "error_message" : alerte,
	#             "message": "Invalid credentials."
	#         })
	# else:
	#     return render(request, "pong/signin.html")


def handle_authentication(request, email, password):
	logger.info("__ D")
	user = authenticate(request, email=email, password=password)
	print("email =", email, "password =", password)
	if user is not None:
		logger.info("__ E")
		request.session['user_id'] = user.id
		if user.is_mfa_enabled:
			return {'redirect': "pong/otp_content.html",
					'url' : reverse("otp")
			}
		else:
			login(request, user)
			return {'redirect': "pong/homepage_content.html",
					'url' : reverse("index")
			}
	else:
		logger.info("__ F")
		logger.info("l'utilisateur est null")
		return {'error_message': "Invalid credentials."}

def signin(request):
	logger.info("__ A")
	if request.user.is_authenticated:
		logger.info("__ B")
		message = "Vous êtes déjà connecté"
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/homepage_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			#messages.add_message(request, messages.INFO, message)
			return HttpResponseRedirect(reverse("index"))

	if request.method == "POST":
		logger.info("__ C")
		email = request.POST.get("email")
		password = request.POST.get("password")
		
		result = handle_authentication(request, email, password)
		logger.debug("email = %s", email)
		logger.debug("password = %s", password)

		if 'error_message' in result:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/signin_content.html", {'error_message': True, 'message': result['error_message']}, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("signin")
				})
			else:
				return render(request, "pong/signin.html", {"error_message": True, "message": result['error_message']})
		else:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string(result['redirect'], {}, request=request)
				return JsonResponse({'html': html,
									'url' : result['url']
				})
			else:
				new_url = result['redirect']
				new_url = new_url.replace("_content", "")
				return HttpResponseRedirect(new_url)

	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/signin_content.html", {}, request=request)
			logger.debug("html in sigin = %s", html)
			return JsonResponse({'html': html,
								'url': reverse("signin")
			})
		else:
			return render(request, "pong/signin.html")

#faire la ologique du otp sur la view otp avec la comparaison du code que le mec aura recu (comme il a deja scanné)
# def otp_view(request):
#     user = NewUser.objects.get(id=(request.session.get('user_id')))
#     message = 'nothing'
#     value = False
#     if request.method == "POST":
#         otp = request.POST["otp"]
#         totp = pyotp.TOTP(user.mfa_hash) #check the secret key
#         if totp.verify(otp): # the case where we can login the user
#             login(request, user)
#             return HttpResponseRedirect(reverse("index"))
#         else: # le cas où la secret key n'est pas la bonne
#             value = True
#             message = 'invalid one time password or the password has expired'      
#     return render(request, 'pong/otp.html' , {
#                                                 'error_message' : {
#                                                                         'value' : value,
#                                                                         'message' : message
#                                                                 }
#                                             })

def otp_view(request):
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	message = 'nothing'
	value = False
	if request.method == "POST":
		otp = ''.join([request.POST.get(f'otp_{i}') for i in range(6)])  # Récupère chaque chiffre du OTP
		totp = pyotp.TOTP(user.mfa_hash)  # Initialise TOTP avec le hachage MFA de l'utilisateur
		if totp.verify(otp):  # Vérifie si le OTP est correct
			login(request, user)  # Connecte l'utilisateur
			#return HttpResponseRedirect(reverse("index"))  # Redirige vers la page d'accueil
			html = render_to_string("pong/homepage_content.html", {}, request=request)
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				return JsonResponse({'html': html,
								'url' : reverse("index")
				})
			else :
				return render(request, 'pong/otp.html' , {
												'error_message' : {
																		'value' : value,
																		'message' : message
																}
											})
		else:
			value = True
			message = 'invalid one time password or the password has expired'
			html = render_to_string("pong/otp_content.html", {'error_message': {
					'value': value,
					'message': message
				}}, request=request)
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				return JsonResponse({'html': html,
								'url' : reverse('otp')
					})
			else :
				return render(request, 'pong/otp.html' , {
												'error_message' : {
																		'value' : value,
																		'message' : message
																}
											})

	return render(request, "pong/otp.html")

# def statistics(request):
	# if not request.user.is_authenticated:
	#     return HttpResponseRedirect(reverse("index"))
	# user = NewUser.objects.get(id=(request.session.get('user_id')))
	# statistics = user.statistic
	# history = []
	# partie = Party.objects.all()
	# for game in partie :
	#     winner = game.winner.pseudo.strip()
	#     loser = game.loser.pseudo.strip()
	#     if ((user.pseudo == winner) or (user.pseudo == loser)) :
	#         history.append(game)
	# game_date = []
	# game_result = []
	# game_result_numeric = []
	# for game in history :
	#     game_date.append(game.date.strftime('%Y-%m-%d'))
	#     if (game.winner.pseudo == user.pseudo) :
	#         game_result.append('Victory')
	#     elif (game.loser.pseudo == user.pseudo) :
	#         game_result.append('Defeat')
	# for result in game_result :
	#     if (result == "Victory") :
	#         game_result_numeric.append(1)
	#     else :
	#         game_result_numeric.append(-1)
	# nbr_day = 1
	# for i in range(1, len(game_date)):
	#     if game_date[i] != game_date[i - 1]:
	#         nbr_day += 1
	# data = {}
	# game_duration = timedelta()
	# for i in range(len(history)):
	#     game_duration += history[i].game_time
	#     if ((i == len(history) - 1) or (history[i].date.strftime('%Y-%m-%d') != history[i + 1].date.strftime('%Y-%m-%d'))) :
	#         data[history[i].date.strftime('%Y-%m-%d')] = game_duration.total_seconds()
	#         game_duration = timedelta()
	# return render(request, "pong/statistics.html", {
	#                                                 'user' : user,
	#                                                 'statistics' : statistics,
	#                                                 'history' : history,
	#                                                 'game_dates_json': json.dumps(game_date),
	#                                                 'game_results_json': json.dumps(game_result_numeric),
	#                                                 'game_duration_json' : json.dumps(data)
	#                                                 })


def update_stats(user) :
	user_statistic = None
	# if not user.statistic:
	data = {
		'history' : [],
		'user_statistic' : None,
		'game_dates_json': [],
		'game_results_json': [],
		'game_duration_json' : {},
	}
	logger.info("On passe la ouai")
	user_statistic, created = Statistic.objects.get_or_create(user=user)
	if created:
		user.statistic = user_statistic
		user.save()
		# user_statistic.nbr_won_parties += 1
	logger.debug("user = %s", user)
	logger.debug("statistics = %s", user.statistic)
	history = []
	partie = Party.objects.all()
	user_here = 0
	for game in partie :
		winner = game.winner.pseudo.strip()
		loser = game.loser.pseudo.strip()
		if ((user.pseudo == winner) or (user.pseudo == loser)) :
			history.append(game)
			user_here += 1
			user.nbr_parties = user_here
			logger.info("C'est ici que ca se passe")
	data['history'] = history
	if user_statistic :
		if user.nbr_parties > (user_statistic.nbr_won_parties + user_statistic.nbr_lose_parties) :
			if user.pseudo == winner :
				logger.info("C'est ici que ca se passe")
				logger.debug(" nbr victoires avant = %d", user_statistic.nbr_won_parties)
				user_statistic.nbr_won_parties += 1
				logger.debug(" nbr victoires apres = %d", user_statistic.nbr_won_parties)
			else :
				user_statistic.nbr_lose_parties += 1
			if game.tournament and game.tournament.name :
				user_statistic.nbr_won_tournaments += 1
			logger.info("J'arrive jusque la")
			user_statistic.save()
		# if user.pseudo == winner:
		# 	if user.statistic:
		# 		user.statistic.nbr_won_parties += 1
		# 	# else:
		# 	# 	# Vous pouvez créer l'objet Statistic ici si nécessaire
		# 	# 	logger.info("on passe dans le else")
		# 	# 	# user_statistic = Statistic.objects.create(user=user)
		# 	# 	user_statistic.nbr_lose_parties += 1
		# 	# 	user_statistic.save()
		# elif user.pseudo == loser :
			
			
	# logger.debug("user_here = %d", user_here)
	logger.debug("user stats = %s", user_statistic)
	game_date = []
	game_result = []
	game_result_numeric = []
	for game in history :
		game_date.append(game.date.strftime('%Y-%m-%d'))
		if (game.winner.pseudo == user.pseudo) :
			game_result.append('Victory')
		elif (game.loser.pseudo == user.pseudo) :
			game_result.append('Defeat')
	for result in game_result :
		if (result == "Victory") :
			game_result_numeric.append(1)
		else :
			game_result_numeric.append(-1)
	# nbr_day = 1
	# for i in range(1, len(game_date)):
	# 	if game_date[i] != game_date[i - 1]:
	# 		nbr_day += 1
	days_of_playing = {}
	game_duration = timedelta()
	user_statistic.total_time_played = timedelta(0)
	for i in range(len(history)):
		game_duration += history[i].game_time
		if user_statistic :
			logger.info("Ici oui")
			logger.debug("time = %s", history[i].game_time)
			user_statistic.total_time_played += history[i].game_time
			logger.debug("time 2 = %s", user_statistic.total_time_played)
			
		if ((i == len(history) - 1) or (history[i].date.strftime('%Y-%m-%d') != history[i + 1].date.strftime('%Y-%m-%d'))) :
			days_of_playing[history[i].date.strftime('%Y-%m-%d')] = game_duration.total_seconds()
			game_duration = timedelta()
	user.statistic = user_statistic
	user.save()
	data['user_statistic'] = user_statistic
	data['game_dates_json'] = json.dumps(game_date)
	data['game_results_json'] = json.dumps(game_result_numeric)
	data['game_duration_json'] = json.dumps(days_of_playing)
	logger.debug("data = %s", data)
	return (data)


def statistics(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	data = {}
	data = update_stats(user)
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/statistics_content.html", {
																		'user' : user,
																		'data' : data
																	}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("statistics")
			})
	else :
		return render(request, "pong/statistics.html", {
													'user' : user,
													'data' : data
													})


def chat_solo(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	chats = Chat.objects.all() #if none 
	message_block = None
	if not chats :
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/add_chat_content.html", {}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("add_chat")
			})
		else:
			return HttpResponseRedirect(reverse("add_chat"))
	list_of_chats = []
	for chat in chats : 
		participants = chat.participants.all()
		for participant in participants :
			logger.debug("user participants = %s", participant)
			if (participant.pseudo == user.pseudo) :
				list_of_chats.append((chat))
	if not list_of_chats :
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/join_chat_content.html", {}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("join_chat")
			})
		else:
			return HttpResponseRedirect(reverse("join_chat"))
	# logger.debug("list of chat = %s", list_of_chats)
	chat_info = {'list_of_chats' : list_of_chats}
	message_info = {}
	for chat in reversed(list_of_chats) :
		messages = chat.messages.all()
		message_info[chat.name] = []
		for message in messages :
			message_info[chat.name].append({
				'message' : message.content,
				'sender' : message.sender.pseudo,
				'time' : message.timestamp.isoformat(),
			})
		name_chat = chat.name
		break
	context = {'chat_info' : chat_info,
				'message_info' : json.dumps(message_info),
				'chat_name' : name_chat,
				'chat_name_json' : json.dumps({'chat_name' : name_chat}),
				'message_block' : message_block,
				'is_solo' : True
	}
	if request.method == 'POST' :
		if request.POST.get('user_target') :
			logger.info("Oui c'est bon")
			user_target = request.POST.get('user_target')
			all_users = NewUser.objects.all()
			# message = None
			found = False
			for founded in all_users : 
				if (user_target == founded.pseudo) :
					if founded.pseudo == user.pseudo :
						message_block = "You can't block yourself"
					else :
						found = True
					break
			if found :
				BlockedUser.objects.create(blocker=user, blocked_user=user_target)
				message_block = f"{user_target} has been blocked"
			elif not found and not message_block :
				message_block = f"{user_target} doesn't exist"
			if message_block :
				context['message_block'] = message_block
			# chat_name_url = None
			# if chat_name :
			# 	chat_name_url = chat_name
			# else: 
			chat_name_url = name_chat
			logger.debug("message = %s", context['message'])
			logger.debug("context = %s", context)
			BlockedUser_all = BlockedUser.objects.all()
			logger.debug("BlockedUser_all = %s", BlockedUser_all)
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/chat_content.html", context, request=request)
			return JsonResponse({'html': html,
									'url' : reverse("chat_solo")
				})
		else:
			return render(request, "pong/chat.html", context)
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/chat_content.html", context, request=request)
		return JsonResponse({'html': html,
								'url' : reverse("chat_solo")
			})
	else:
		return render(request, "pong/chat.html", context)


def chat_room(request, chat_name):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	chats = Chat.objects.all() #if none
	message_block = None
	if not chats :
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/add_chat_content.html", {'chat_info' : {
																					'value' : True,
																					'list_of_chats' : list_of_chats,
																				}}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("add_chat")
			})
		else:
			return HttpResponseRedirect(reverse("add_chat"))
	list_of_chats = []
	for chat in chats : 
		participants = chat.participants.all()
		for participant in participants :
			logger.debug("user participants = %s", participant)
			if (participant.pseudo == user.pseudo) :
				list_of_chats.append((chat))
	if not list_of_chats :
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/join_chat_content.html", {}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("join_chat")
			})
		else:
			return HttpResponseRedirect(reverse("join_chat"))
	# logger.debug("list of chat = %s", list_of_chats)
	chat_info = {'list_of_chats' : list_of_chats}
	message_info = {}
	context = {'chat_info' : None,
					'message_info' : None,
					'chat_name' : None,
					'chat_name_json' : None,
					'message_block' : message_block,
					'is_solo' : False
		}
	if not chat_name :
		for chat in reversed(list_of_chats) :
			messages = chat.messages.all()
			message_info[chat.name] = []
			for message in messages :
				message_info[chat.name].append({
					'message' : message.content,
					'sender' : message.sender.pseudo,
					'time' : message.timestamp.isoformat(),
				})
			name_chat = chat.name
			break
		context['chat_info'] = chat_info
		context['message_info'] = json.dumps(message_info)
		context['chat_name'] = name_chat
		context['chat_name_json'] = json.dumps({'chat_name' : name_chat})
	else :
		toggle = True
		for chat in reversed(list_of_chats) :
			if (chat.name == chat_name) :
				messages = chat.messages.all()
				message_info[chat.name] = []
				for message in messages :
					# blocked_object = BlockedUser.objects.all()
					# blocked_list = []
					# if blocked_object :
					# 	for blocked in blocked_object :
					# 		if user.pseudo == blocked.blocker.pseudo :
					# 			if message.sender == blocked.blocked.pseudo :
					# 				toggle = False
					toggle = is_blocked(user, message.sender)
					if not toggle :
						message_info[chat.name].append({
							'message' : message.content,
							'sender' : message.sender.pseudo,
							'time' : message.timestamp.isoformat(),
					})
				break
			# context = {'chat_info' : chat_info,
			# 			'message_info' : json.dumps(message_info),
			# 			'chat_name' : chat_name,
			# }
		context['chat_info'] = chat_info
		context['message_info'] = json.dumps(message_info)
		context['chat_name'] = chat_name
		context['chat_name_json'] = json.dumps({'chat_name' : chat_name})
	if request.method == "POST" : 
		if request.POST.get("message_content") :
			message_content = request.POST.get("message_content")
			logger.debug("message_content = %s", message_content)
			logger.debug("context = %s", context)
			# chat_id = request.POST.get('chat_id')
			# logger.debug("chat_id = %s", chat_id)
			# chat = get_object_or_404(Chat, id=chat_id)
			# logger.debug("chat = %s", chat)
			chat_name_url = None
			if chat_name :
				chat_name_url = chat_name
			else: 
				chat_name_url = name_chat
			chat_object = Chat.objects.get(name=chat_name_url)
			logger.debug("chat_objet = %s", chat_object)
			message_object = Message.objects.create(sender=user, content=message_content)
			message_object.save()
			send_message(chat_object, message_object)
			chat_object.save()
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/chat_content.html", context, request=request)
				return JsonResponse({'html': html,
										'url' : (f"{chat_name_url}")
					})
				return render(request, "pong/chat.html", context)
		if request.POST.get('user_target') :
			logger.info("Oui c'est bon")
			user_target = request.POST.get('user_target')
			if not user_target :
				logger.info("On passe par ce chemin")
				message = " Error : Field Empty"
				context['message_block'] = message
				if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/chat_content.html", context, request=request)
					return JsonResponse({'html': html,
											'url' : (f"{chat_name_url}")
						})
				else:
					return render(request, "pong/chat.html", context)
			logger.debug("user_target = %s", user_target)
			all_users = NewUser.objects.all()
			message = None
			found = False
			for founded in all_users : 
				if (user_target == founded.pseudo) :
					if founded.pseudo == user.pseudo :
						message = "You can't block yourself"
					else :
						found = True
					break
			if found :
				BlockedUser.objects.create(blocker=user, blocked_user=user_target)
				message = f"{user_target} has been blocked"
			elif not found and not message :
				message = f"{user_target} doesn't exist"
			if message :
				context['message_block'] = message
			chat_name_url = None
			if chat_name :
				chat_name_url = chat_name
			else: 
				chat_name_url = name_chat
			logger.debug("message_block = %s", context['message_block'])
			logger.debug("context = %s", context)
			BlockedUser_all = BlockedUser.objects.all()
			logger.debug("BlockedUser_all = %s", BlockedUser_all)
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/chat_content.html", context, request=request)
				return JsonResponse({'html': html,
										'url' : (f"{chat_name_url}")
					})
			else:
				return render(request, "pong/chat.html", context)
	else:
		chat_name_url = None
		if chat_name :
			chat_name_url = chat_name
		else: 
			chat_name_url = name_chat
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/chat_content.html", context, request=request)
			return JsonResponse({'html': html,
									'url' : (f"{chat_name_url}")
				})
		return render(request, "pong/chat.html", context)


def check_private_possibility(user) :
	user_friends = get_friends(user)
	info_add_chat = {
		'token' : None,
		'users_ok' : [],
		'blocked_users' : []
	}
	if not user_friends :
		info_add_chat['token'] = False
		return info_add_chat
	blocked_object = BlockedUser.objects.all()
	blocked_list = []
	if blocked_object :
		for blocked in blocked_object :
			if user.pseudo == blocked.blocker.pseudo :
				for friend in user_friends :
					if friend.pseudo == blocked.blocked_user.pseudo :
						blocked_list.append(friend)
		for friend in user_friends :
			toggle = False
			for users_blocked in blocked_list : 
				if friend.pseudo == users_blocked.pseudo :
					toggle = True
					break
			if not toggle :
				info_add_chat['users_ok'].append(friend)
		info_add_chat['blocked_users'] = blocked_list
	else :
		for friend in user_friends :
			info_add_chat['users_ok'].append(friend)
	# if info_add_chat['users_ok'] or info_add_chat:
	info_add_chat['token'] = True
	logger.debug("info_add_chat = %s", info_add_chat)
	return (info_add_chat)

def is_in_users(username) :
	# error_message = None
	toggle = False
	all_users = NewUser.objects.all()
	for user_solo in all_users : 
		if username == user_solo.pseudo :
			toggle = True
			break
	if not toggle :
		return (None)
	return user_solo

def is_in_friends_list(username, friend_list) : 
	toggle = False
	error_message = None
	for friend in friend_list : 
		if friend.pseudo == username :
			toggle = True
			break
	if not toggle : 
		error_message = f"{username} is not your friend"
	return (error_message)

def is_blocked_add_chat(username, blocked_list) :
	toggle = False
	error_message = None
	for blocked in blocked_list : 
		logger.debug("blocked.pseudo = %s", blocked.pseudo)
		logger.debug("username = %s", username)
		if blocked.pseudo == username :
			toggle = True
			break
	if toggle :
		error_message = f"{username} is blocked"
	# logger.debug("blocked_list = %s", blocked_list)
	# # if username in blocked_list :
	return (error_message)


def is_blocked(user, target) :
	blocked_object = BlockedUser.objects.all()
	if blocked_object :
		for block in blocked_object :
			if block.blocker.pseudo == user.pseudo and block.blocked_user.pseudo == target.pseudo :
				return (True)
	return False

# def block_user(request) :
# 	if request.method == 'POST' :
# 		logger.info("Oui c'est bon")
# 		user = NewUser.objects.get(id=(request.session.get('user_id')))
# 		user_target = request.POST.get('user_target')
# 		all_users = NewUser.objects.all()
# 		message = None
# 		found = False
# 		for user in all_users : 
# 			if (user_target == user.pseudo) :
# 				found = True
# 				break
# 		if found :
# 			BlockedUser.objects.create(blocker=user, blocked_user=user_target)
# 			message = f"{user_target} has been blocked"
# 		else :
# 			message = f"{user_target} doesn't exist"
# 		logger.debug("message = %s", message)
# 		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
# 			return JsonResponse({'message' : message})
# 		else:
# 			return redirect('chat')
# 	else :
# 		response_data = {'error': 'Invalid request method'}
# 		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
# 			return JsonResponse(response_data)
# 		else:
# 			return redirect('chat')

def add_chat(request) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	private_possibility = False
	add_chat_info = check_private_possibility(user)
	if request.method == "POST" :
		if (request.POST.get("chat_name")) :
			chat_name = request.POST.get("chat_name")
			logger.debug("chat_name = %s", chat_name)
			chats = Chat.objects.all()
			logger.debug("chats = %s", chats)
			error_message = None
			for chat in chats :
				logger.debug("chat_name for = %s", chat_name)
				logger.debug("chat.name = %s", chat.name)
				if (chat_name == chat.name) :
					logger.info("Je rentre dedans")
					error_message = "Chat already exist. Please try with another one"
					break
			if (error_message) :
				logger.info("Je rentre dans error_message")
				logger.debug("error_message = %s", error_message)
				if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_chat_content.html", {'message': {
																		'value' : True,
																		'error_message' : error_message},
																		'add_chat_info' : add_chat_info
																		}, request=request)
					return JsonResponse({'html': html,
										'url' : reverse("add_chat")
					})
				else:
					return render(request, "pong/add_chat.html", {'message': {
																		'value' : True,
																		'error_message' : error_message},
																		'add_chat_info' : add_chat_info})
			chat, created = Chat.objects.get_or_create(name=chat_name)
			user_participant, created = Participant.objects.get_or_create(user=user, chat=chat)
			chat.save()
			user_participant.save()
			error_message = f"Chat {chat_name} was created successfully"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_chat_content.html", {'message': {
																		'value' : True,
																		'error_message' : error_message},
																		'add_chat_info' : add_chat_info}, request=request)
					return JsonResponse({'html': html,
										'url' : reverse("add_chat")
					})
			else:
				return render(request, "pong/add_chat.html", {'message': {
																		'value' : True,
																		'error_message' : error_message},
																		'add_chat_info' : add_chat_info})
		if request.POST.get("private_chat") :
			logger.info("On se retrouve bien ici")
			friend_name = request.POST.get("private_chat")
			logger.debug("friend_name = %s", friend_name)
			logger.debug("friend_name = %s", type(friend_name))
			error_message = None
			other_user = is_in_users(friend_name)
			if not other_user : 
				error_message = f"{friend_name} user doesn't exist"
			if not error_message :
				friend_list = get_friends(user)
				logger.debug("friend_list = %s", friend_list)
				error_message = is_in_friends_list(friend_name, friend_list)
				if not error_message :
					error_message = is_blocked_add_chat(friend_name, add_chat_info['blocked_users'])
					if not error_message :
						error_message = "Tous les filtres ont ete passes"
						chat_name = other_user.pseudo + " et " + user.pseudo
						chat_private, created = Chat.objects.get_or_create(name=chat_name, is_private=True)
						participant1, created = Participant.objects.get_or_create(user=user, chat=chat_private)
						participant2, created = Participant.objects.get_or_create(user=other_user, chat=chat_private)
						chat_private.save()
						participant1.save()
						participant2.save()
						error_message =  f"You are now in private conversation with {other_user.pseudo}"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_chat_content.html", {'message': {
																		'value' : True,
																		'error_message' : error_message},
																		'add_chat_info' : add_chat_info}, request=request)
					return JsonResponse({'html': html,
										'url' : reverse("add_chat")
					})
			else:
				return render(request, "pong/add_chat.html", {'message': {
																		'value' : True,
																		'error_message' : error_message},
																		'add_chat_info' : add_chat_info})
	else : 
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/add_chat_content.html", {'add_chat_info' : add_chat_info}, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("add_chat")
				})
		else:
			return render(request, "pong/add_chat.html", {'add_chat_info' : add_chat_info})


def join_chat(request) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	all_chats = Chat.objects.all()
	list_of_chats = []
	for chat in all_chats :
		participants = chat.participants.all()
		is_in = False
		for users in participants :
			if (users == user) :
				is_in = True
				break
		if not is_in :
			list_of_chats.append(chat)
	if request.method == "POST" :
		chat_name = request.POST.get("chat_name")
		# all_chats = Chat.objects.all()
		error_message = None
		message = None
		chat_exist = False
		for chat in all_chats :
			logger.info("on passe bien dans la boucle des chat")
			if (chat_name == chat.name) :
				chat_exist = True
				participants = chat.participants.all()
				for users in participants :
					if (users == user) :
						error_message = "You already are in that chat"
						break
				if not error_message :
					if chat.is_private == True :
						error_message = "You cant't join that chat, it is private"
					else : 
						Participant.objects.get_or_create(user=user, chat=chat)
						message = f"YOU JOINED {chat_name}"
				break
		if not chat_exist :
			logger.info("On passe la aussi")
			error_message = f"{chat_name} doesn't exist. Please try again"
		logger.debug("error_message : %s", error_message)
		logger.debug("list_of_chats : %s", list_of_chats)
		if error_message :
			context = {
				'chat_info' : {
					'value' : True,
					'error_message' : error_message,
					'list_of_chats' : list_of_chats,
				}
			}
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/join_chat_content.html", context, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("join_chat")
				})
			else:
				return render(request, "pong/join_chat.html", context)
		else :
			context = {
				'chat_info' : {
					'value' : True,
					'message' : message,
					'list_of_chats' : list_of_chats,
				}
			}
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/join_chat_content.html", context, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("join_chat")
				})
			else:
				return render(request, "pong/join_chat.html", context)
	else :
		context = {
			'chat_info' : {
				'value' : True,
				'list_of_chats' : list_of_chats,
			}
		}
		logger.debug("context value = %s", context['chat_info']['value'])
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/join_chat_content.html", context, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("join_chat")
			})
		else:
			return render(request, "pong/join_chat.html", context)


def render_chat(request, chat_name) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	all_chats = Chat.objects.all()
	update_message = {}
	for chat in all_chats :
		if chat.name == chat_name :
			message_chat = chat.messages.all()
			update_message[chat.name] = []
			for message in message_chat :
				update_message[chat.name].append({
					'message' : message.content,
					'sender' : message.sender.pseudo,
					'time' : message.timestamp.isoformat(),
				})
			# logger.debug("message_chat = %s", message_chat)
			return JsonResponse({
				'chat_found' : True,
				'update_message' : update_message
			})
	return JsonResponse({
		'chat_found' : False,
	})


# def logout_view(request):
	# if request.user.is_authenticated:
	#     logout(request)
	# return redirect('login')


# def logout_view(request):
	# if request.user.is_authenticated:
	#     logout(request)
	
	# if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#     html = render_to_string("pong/login_content.html", {}, request=request)
	#     return JsonResponse({'html': html})``
	# else:
	#     return HttpResponseRedirect(reverse('login'))

def leave_chat(request) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	logger.debug("THE USER IS = %s", user)
	all_chats = Chat.objects.all()
	list_of_chats = []
	for chat in all_chats :
		participants = chat.participants.all()
		is_in = False
		for users in participants :
			logger.debug("chats = %s", chat)
			logger.debug("user = %s", users)
			if (users.pseudo == user.pseudo) :
				is_in = True
			if is_in :
				list_of_chats.append(chat)
				break
	logger.debug("list_of_chats = %s", list_of_chats)
	context = {
		'error_message' : None,
		'message' : None,
		'list_of_chats' : []
	}
	if list_of_chats : 
		context['list_of_chats'] = list_of_chats
	if request.method == "POST" :
		chat_exist = False
		chat_name = request.POST.get("chat_name")
		for chat in all_chats :
			if chat.name == chat_name :
				chat_exist = True
				break
		if chat_exist :
			user_in_chat = False
			for chats in list_of_chats :
				if chats.name == chat_name :
					user_in_chat = True
					break
			# if user_in_chat :
			# 	participant_pool = chats.participants.all()
			# 	for participant in participant_pool :
			# 		if participant.pseudo == user.pseudo :
			# 			participant.delete()
			# 			message = f"You leaved {chat_name}"
			# 			context['message'] = message
			# 	participant_pool = chats.participants.all()
			# 	if not participant_pool :
			# 		chats.delete()
			if user_in_chat:
				participant_pool = chats.participants.all()
				participant_to_remove = None
				for participant in participant_pool:
					if participant.pseudo == user.pseudo:
						participant_to_remove = participant
						break
				if participant_to_remove:
					chats.participants.remove(participant_to_remove)
					message = f"You leaved {chats.name}"
					context['message'] = message
				participant_pool = chats.participants.all()
				if not participant_pool:
					chats.delete()
				else :
					chats.save()
			else :
				error_message = f"You are not in that chat"
				context['error_message'] = error_message
		else :
			error_message = f"{chat_name} doesn't exist"
			context['error_message'] = error_message
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/leave_chat_content.html", context, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("leave_chat")
			})
	else:
		return render(request, "pong/leave_chat.html", context)



def logout_view(request):
	if request.user.is_authenticated:
		user = NewUser.objects.get(id=(request.session.get('user_id')))
		user.is_active = False
		user.save()
		logout(request)

	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/login_content.html", {}, request=request)
		return JsonResponse({'html': html})
	else:
		return HttpResponseRedirect(reverse('login'))


def profile_view(request):
	#gérer block user
	#gérer cliquer sur un user et redirigé vers profil plus simple
	#faire spa
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 
								'url' : reverse("login")
								})
		else:
			return HttpResponseRedirect(reverse("login"))
 
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	url = pyotp.totp.TOTP(user.mfa_hash).provisioning_uri(name=user.email, issuer_name="Pong")
	qr = qrcode.make(url)
	buffered = BytesIO()
	qr.save(buffered)
	qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
	try:
		user_avatar = user.avatar.url
	except ValueError:
		user_avatar = None
	friends = get_friends(user)
	password_form_errors = []
	other_error  = {
		"avatar" : None,
		"email" : None,
		"pseudo" : None
	}

	
	if request.method == "POST":
		if request.POST.get("options"):
			choice = request.POST.get("options")
			if choice == "enabled":
				user.is_mfa_enabled = True
				user.save()
			else:
				user.is_mfa_enabled = False
				user.save()
			#return HttpResponseRedirect(reverse("profile"))
		if request.POST.get("change_pseudo"):
			if user.pseudo is not request.POST.get("change_pseudo"):
				try:
					test = NewUser.objects.get(pseudo=request.POST.get("change_pseudo"))
					other_error["pseudo"] = "this pseudo already exist"
				except NewUser.DoesNotExist:
					user.pseudo = request.POST.get("change_pseudo")
					user.save()
			else:
				other_error["pseudo"] = "you are already name like this"
				
		if request.FILES.get("change_avatar"):
			user.avatar = request.FILES.get("change_avatar")
			user.save()
			user_avatar = user.avatar.url
			update_session_auth_hash(request, user)
		if request.POST.get("change_email"):
			if user.email is not request.POST.get("change_email"):
				try:
					test = NewUser.objects.get(email=request.POST.get("change_email"))
					other_error["email"] =  "this email already exist"
				except NewUser.DoesNotExist:
					user.email = request.POST.get("change_email")
					user.save()
					update_session_auth_hash(request, user)  
			else:
				other_error["email"] = "your email is already this one"

		if request.POST.get("old_password"):
			old_password = request.POST.get("old_password")
			new_password1 = request.POST.get("new_password1")
			new_password2 = request.POST.get("new_password2")
			
			if new_password1 and new_password2 and old_password:
				if new_password1 == new_password2:
					if user.check_password(old_password):
						user.set_password(new_password1)
						user.save()
						update_session_auth_hash(request, user)  # Important to update session
						return HttpResponseRedirect(reverse("index"))
					else:
						password_form_errors.append('Old password is incorrect.')
				else:
					password_form_errors.append('New passwords do not match.')
			else:
				password_form_errors.append('Please fill out all password fields.')
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/profile_content.html", {
														'user_info' : {
															'user_choice' : user.is_mfa_enabled,
															'user_url'    : qr_base64,
															'user_pseudo' : user.pseudo,
															'user_email' : user.email,
															'user_avatar' : user_avatar,
															'user_friends' : friends,
															'user_blocked_users': "test"

															},
															'password_form_errors': password_form_errors,
															'other_error': other_error}, request=request)
		return JsonResponse({'html': html,
								'url' : reverse("profile")
								})
	else:    
		return render(request, "pong/profile.html", {
														'user_info' : {
															'user_choice' : user.is_mfa_enabled,
															'user_url'    : qr_base64,
															'user_pseudo' : user.pseudo,
															'user_email' : user.email,
															'user_avatar' : user_avatar,
															'user_friends' : friends,
															'user_blocked_users': "test"

															},
															'password_form_errors': password_form_errors,
															'other_error': other_error
													})


def recup_user_info(user) :
	url = pyotp.totp.TOTP(user.mfa_hash).provisioning_uri(name=user.email, issuer_name="Pong")
	qr = qrcode.make(url)
	buffered = BytesIO()
	qr.save(buffered)
	qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
	try:
		user_avatar = user.avatar.url
	except ValueError:
		user_avatar = None
	friends = get_friends(user)
	other_error  = {
		"avatar" : None,
		"email" : None,
		"pseudo" : None
	}
	user_info = {
					'user_info' : {
						'user_choice' : user.is_mfa_enabled,
						'user_url' : qr_base64,
						'user_pseudo' : user.pseudo,
						'user_avatar' : user_avatar,
						'user_friends' : friends,
					}, 'other_error': other_error
	}
	return user_info



# def add_friends(request):
	# if not request.user.is_authenticated:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#         html = render_to_string("pong/login_content.html", {}, request=request)
	#         return JsonResponse({'html': html})
	#     else:
	#         return HttpResponseRedirect(reverse("login"))

	# user = NewUser.objects.get(id=(request.session.get('user_id')))

	# if request.method == "POST":
	#     friend_pseudo = request.POST.get("friend_pseudo")
	#     friend_user = None
	#     try:
	#         friend_user = NewUser.objects.get(pseudo=friend_pseudo)
	#     except NewUser.DoesNotExist:
	#         friend_user = None
	#     #empecher d'etre amis avec sois même
	#     if ( friend_user is not None) and (user.id is not friend_user.id) :
	#         # Check if they are already friends
	#         if Friendship.objects.filter(person1=user, person2=friend_user).exists() or Friendship.objects.filter(person1=friend_user, person2=user).exists():
	#             if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are already friends"
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#             else:
	#                 return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are already friends"
	#                                                             }
	#                                         })

	#     # Create the friendship
	#         Friendship.objects.create(person1=user, person2=friend_user)
	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#             html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are now friends"
	#                                                             }
	#                                         }, request=request)
	#             return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#         else:
	#             return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are now friends"
	#                                                             }
	#                                         })
			
	#     else:
	#         if friend_user is None:
	#             message = "this user doesn't exist"
	#         else:
	#             message = "you can't add yourself as friend"
	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#         else:
	#             return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         })
	# else:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#     else:
	#         return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                         })


def add_friends(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html})
		else:
			return HttpResponseRedirect(reverse("login"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	friend_user = get_friends(user)
	logger.debug("la liste des users amis : %s", friend_user)
	all_users = NewUser.objects.all()
	logger.debug("la liste des users  : %s", all_users)
	users_list = []
	for users in all_users :
		# logger.debug("amis = %s", users)
		if users not in friend_user and users != user and users.pseudo != "admin":
			users_list.append(users)
	logger.debug("la liste des users non amis : %s", users_list)
	if request.method == "POST":
		friend_pseudo = request.POST.get("friend_pseudo")
		friend_user = None
		try:
			friend_user = NewUser.objects.get(pseudo=friend_pseudo)
		except NewUser.DoesNotExist:
			friend_user = None
		#empecher d'etre amis avec sois même
		if ( friend_user is not None) and (user.id is not friend_user.id) :
			# Check if they are already friends
			if Friendship.objects.filter(person1=user, person2=friend_user).exists() or Friendship.objects.filter(person1=friend_user, person2=user).exists():
				if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : "you are already friends"
																}, 'users_list' : users_list,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
				else:
					return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : "you are already friends"
																}, 'users_list' : users_list,
											})

		# Create the friendship
			Friendship.objects.create(person1=user, person2=friend_user)
			logger.debug("friend_user = %s", friend_user)
			temp = friend_user.pseudo.upper()
			logger.debug("friend_user apres = %s", friend_user)
			message = temp + " IS NOW YOUR FRIEND"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											}, request=request)
				return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
			else:
				return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											})

		else:
			if friend_user is None:
				message = "this user doesn't exist"
			else:
				message = "you can't add yourself as friend"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
			else:
				return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											})
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'users_list' : users_list,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
		else:
			return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'users_list' : users_list,
											})




# def delete_friends(request):
	# if not request.user.is_authenticated:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#         html = render_to_string("pong/login_content.html", {}, request=request)
	#         return JsonResponse({'html': html})
	#     else:
	#         return HttpResponseRedirect(reverse("login"))

	# user = NewUser.objects.get(id=(request.session.get('user_id')))

	# if request.method == "POST":
	#     friend_pseudo = request.POST.get("friend_pseudo")
	#     friend_user = None
	#     try:
	#         friend_user = NewUser.objects.get(pseudo=friend_pseudo)
	#     except NewUser.DoesNotExist:
	#         friend_user = None
	
	#     if ( friend_user is not None) and (user.id is not friend_user.id) :
	#         friendship = Friendship.objects.filter(Q(person1=user, person2=friend_user) | Q(person1=friend_user, person2=user)).first()
	#         if friendship:
	#             friendship.delete()
	#         else:
	#             message = "you are not friends"
	#             if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                             })

		   
	#         #succes delete friend 
	#         message = "you are not friends anymore"
	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#             html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#             return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#         else:
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                             }) 
	#     else:
	#         if friend_user is None:
	#             message = "this user doesn't exist"
	#         else:
	#             message = "you can't delete yourself as friend"

	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#             html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#             return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#         else:
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                             }) 
	# else:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#         html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                         }, request=request)
	#         return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#     else:
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                                             }
	#                                                             )


def delete_friends(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html})
		else:
			return HttpResponseRedirect(reverse("login"))

	user = NewUser.objects.get(id=(request.session.get('user_id')))

	user_friend = get_friends(user)

	if request.method == "POST":
		friend_pseudo = request.POST.get("friend_pseudo")
		friend_user = None
		try:
			friend_user = NewUser.objects.get(pseudo=friend_pseudo)
		except NewUser.DoesNotExist:
			friend_user = None

		if ( friend_user is not None) and (user.id is not friend_user.id) :
			friendship = Friendship.objects.filter(Q(person1=user, person2=friend_user) | Q(person1=friend_user, person2=user)).first()
			if friendship:
				friendship.delete()
			else:
				message = "you are not friends"
				if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
												})


			#succes delete friend
			message = "you are not friends anymore"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
											}, request=request)
				return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
			else:
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
												})
		else:
			if friend_user is None:
				message = "this user doesn't exist"
			else:
				message = "you can't delete yourself as friend"

			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
											}, request=request)
				return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
			else:
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
												})
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'user_friend' : user_friend,
											}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
		else:
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'user_friend' : user_friend,
																})


def other_profile(request, username) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html})
		else:
			return HttpResponseRedirect(reverse("login"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	logger.debug("user = %s", user)
	logger.info("Je passe la dans other profile")
	# username = username
	logger.debug("username = %s", username)
	data = {}
	context = {
		'user_target' :{
						'token' : False
		}
	}
	logger.debug("context = %s", context)
	all_users = NewUser.objects.all()
	user_target = None
	is_friend = False
	logger.debug("all Users = %s", all_users)
	for user_found in all_users :
		if user_found.pseudo == username :
			user_target = user_found
			break
	if user_target.pseudo == user.pseudo :
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/profile_content.html", context, request=request)
			return JsonResponse({'html': html,
								'url' : ("profile")})
		else:
			return render(request, "pong/profile.html", context)
	# logger.debug("user_target email = %s", user_target.email)
	# logger.debug("user_target pseudo = %s", user_target.pseudo)
	# logger.debug("user_target password = %s", user_target.password)
	logger.debug("user_target avatar = %s", user_target.avatar)
	# logger.debug("user_target stats = %s", user_target.statistic)
	# logger.debug("user_target = %s", user_target)
	user_friend = get_friends(user)
	try:
		user_target_avatar = user_target.avatar.url
	except ValueError:
		user_target_avatar = None
	logger.debug("friends = %s", user_friend)
	for friend in user_friend : 
		if friend.pseudo == user_target.pseudo :
			is_friend = True
			break
	logger.debug("user_target.statistic = %s", user_target.statistic)
	data = update_stats(user_target)
	logger.debug("data = %s", data)
	history = []
	partie = Party.objects.all()
	for game in partie :
		winner = game.winner.pseudo.strip()
		loser = game.loser.pseudo.strip()
		if ((user.pseudo == winner) or (user.pseudo == loser)) :
			history.append(game)
	context = {
		'user_target' : {
						'token' : True,
						'username' : user_target.pseudo,
						'is_friend' : is_friend,
						'user_avatar' : user_target_avatar,
						'statistics' : user_target.statistic,
						'history' : history,
		}
	}
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/other_profile_content.html", context, request=request)
			return JsonResponse({'html': html,
								'url' : (f"/other_profile/{username}")})
	else:
		return render(request, "pong/other_profile.html", context)

# user_id = request.session.get('user_id')
# 	if not user_id:
# 		return HttpResponseRedirect(reverse("index"))

# 	user = get_object_or_404(NewUser.objects.select_related('statistic'), id=user_id)

# 	# Déboguer la valeur de user.statistic
# 	logger.debug("User: %s", user)
# 	logger.debug("User.statistic: %s", user.statistic)

# 	# Vérifier si user.statistic est nul ou non
# 	if user.statistic is None:
# 		logger.info("On passe la")
# 		user_statistic, created = Statistic.objects.get_or_create(user=user)
# 		user_statistic.save()
# 	else:
# 		logger.info("Statistique déjà existante")



