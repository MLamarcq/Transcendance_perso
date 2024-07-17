USERNAME :=$(shell whoami)
VOLUME := $(sudo docker volume ls -q)

all:
	sudo docker-compose -f docker-compose.yml build --no-cache;
	sudo docker-compose -f docker-compose.yml up -d;

logs:
	sudo docker logs backend
	sudo docker logs database

clean:
	sudo docker container stop database
	sudo docker container stop backend
	sudo docker container stop nginx
	sudo docker network rm transcendance
	# sudo docker volume rm $(VOLUME)

fclean: clean
	sudo rm -rf /home/gael/Desktop/data/database/*
	sudo rm -rf /home/gael/Desktop/data/backend/*
	sudo docker rm database
	sudo docker rm backend
	# sudo docker-compose down -v
	sudo docker system prune -af

re: fclean all

.Phony: all logs clean fclean