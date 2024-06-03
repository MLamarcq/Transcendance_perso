log()
{
	BLUE='\033[0;34m'
	NC='\033[0m'
	echo -e "${BLUE}$(date +"%Y-%m-%d %H:%M:%S") - ${NC}$1"
}

sleep 1

cd /code

if [ $? -ne 0 ]; then
	log "Une erreur s'est produite lors de l'exécution de la commande -> python3.12 manage.py makemigrations."
	log "Code de sortie: $?"
	exit 1  # Quitter le script avec un code d'erreur
fi

log "migration in progess.."

sleep 1

python3.12 manage.py makemigrations

if [ $? -ne 0 ]; then
	log "Une erreur s'est produite lors de l'exécution de la commande -> python3.12 manage.py makemigrations."
	log "Code de sortie: $?"
	exit 1  # Quitter le script avec un code d'erreur
fi

python3.12 manage.py migrate

if [ $? -ne 0 ]; then
	log "Une erreur s'est produite lors de l'exécution de la commande -> python3.12 manage.py migrate."
	log "Code de sortie: $?"
	exit 1  # Quitter le script avec un code d'erreur
fi

python3.12 create_superuser.py

if [ $? -ne 0 ]; then
	log "Une erreur s'est produite lors de l'exécution de la commande -> python3.12 manage.py shell -c."
	log "Code de sortie: $?"
	exit 1  # Quitter le script avec un code d'erreur
fi

python3.12 manage.py runserver 0.0.0.0:8000

if [ $? -ne 0 ]; then
	log "Une erreur s'est produite lors de l'exécution de la commande -> python3.12 manage.py runserver 0.0.0.0:8000"
	log "Code de sortie: $?"
	exit 1  # Quitter le script avec un code d'erreur
fi

log "End of script, everything fine"
