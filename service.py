import firebase_admin
from firebase_admin import credentials, firestore, messaging
from neo4j import GraphDatabase, basic_auth
from celery import Celery

# Firebase Setup
cred = credentials.Certificate("SoiscanServiceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# DB setup
graph_user = "neo4j"
graph_password = "0oIXkYwWMhaEfmccsTTQJeMz3nHScaPbrE451Cq28k0"
graph_url = "neo4j+s://a0e76398.databases.neo4j.io:7687"
driver = GraphDatabase.driver(graph_url, auth=basic_auth(graph_user, graph_password))

# Celery Setup
# Broker sayamastya lavinmq two million message
broker_mastya_lavinmq = "amqps://wcyzdxsn:SAJ5131CYZTwhkEYar1PFOBbUdOJFQK6@fuji.lmq.cloudamqp.com/wcyzdxsn"
broker_mastya_rabbitmq = "amqps://wicukpje:5A-R1lPa04tmhmSbM3TQjlE4XWfA_sne@armadillo.rmq.cloudamqp.com/wicukpje"
broker_setyawanarik_rabbitmq = "amqps://rbjnwlzo:kdTz3Q6edDXpyFnsZi_P6Hrcmh823xEq@armadillo.rmq.cloudamqp.com/rbjnwlzo"
app = Celery("tasks", broker=broker_mastya_lavinmq)

def search(iduser,epoch_low,epoch_high, email_list):
	with driver.session() as session:
		GetInteractionUser = session.run("match (a:Users {UserID:$UserID})-[r1:MEET]->(b:Interactions)<-[r2:MEET]-(c:Users) where b.datetime_sql >= $start and b.datetime_sql <= $end return a,b,c",UserID=iduser,start=epoch_low,end=epoch_high)

		for i in GetInteractionUser:
			node_data = i.data()
			Email = node_data['c']['Email']
			if Email not in email_list:
				email_list.append(Email)
				search(node_data['c']['UserID'],epoch_low,epoch_high,email_list)

@app.task
def notifyuser(iduser,epoch_low,epoch_high):
	email_list = []
	# iduser="6c802247-212a-4129-b7e4-6f2526dc235e"
	# epoch_low=1664902800.0
	# epoch_high=1665075600.0
	search(iduser,epoch_low,epoch_high,email_list)
	for i in email_list:
		docs = db.collection("fcm").document(i).get()
		if docs.to_dict() != None:
			FCMTOKEN = docs.to_dict()['token']

			# Set Notification body
			notif = messaging.Notification(
					title="COVID-19 Tracing Aleart",
					body="We trace someone that connect to you right now is possibly having COVID-19. please check if you have any symptoms of COVID-19."
				)

			# Set Notification send
			message = messaging.MulticastMessage(
					notification=notif,
					tokens=FCMTOKEN
				)

			# send Notif
			response = messaging.send_multicast(message)

	return email_list
