FROM debian:latest

# Installo i pacchetti necessari
RUN apt-get update

RUN apt-get upgrade -y

RUN apt-get install -y --no-install-recommends build-essential libssl-dev
RUN rm -rf /var/lib/apt/lists/*

# Creo la directory di lavoro
WORKDIR /app

# Copio i file della directory corrente nel container
COPY . /app

# Eseguo make
RUN make

# Eseguo il programma compilato (modifica 'myprogram' con il nome del tuo eseguibile)
ENTRYPOINT ["./socat-plus"]

