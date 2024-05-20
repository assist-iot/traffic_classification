#Deriving the latest base image
FROM gitlab.assist-iot.eu:5050/enablers-registry/public/traffic-classification/ml:1.0.0

#Labels as key value pair
LABEL Maintainer="alforlea@upv.es"
# Any working directory can be chosen as per choice like '/' or '/home' etc

ENV TZ=Europe/Madrid
ENV ML_PORT=10111
ENV BASE_FOLDER="/app/ML_model"

# i have chosen /usr/app/src
WORKDIR /app

#to COPY the remote file at working directory in container
COPY . ./

ENV PYTHONUNBUFFERED=1

# configure the container to run in an executed manner
# Next volume will include /model, /data and /preprocessed folders
#VOLUME /ML_folder
ENTRYPOINT [ "python3" ]
CMD ["view.py" ]
