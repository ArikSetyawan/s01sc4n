from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse
from neo4j import GraphDatabase, basic_auth

# Graph DB Connection
graph_user = "neo4j"
graph_password = "0oIXkYwWMhaEfmccsTTQJeMz3nHScaPbrE451Cq28k0"
graph_url = "neo4j+s://a0e76398.databases.neo4j.io:7687"

driver = GraphDatabase.driver(graph_url, auth=basic_auth(graph_user, graph_password))
session = driver.session()

app = Flask(__name__)
api = Api(app)

# Custom Function
# Token Check
def check_token(Token):
    user = Users.select().where(Users.Token == Token)
    if user.exists():
        user = user.dicts().get()

        # cek expire
        now = int(time.time())
        if now > int(user['Expire_Token']):
            return "Expire"
        else:
            return "Ok"
    else:
        return "Bad Token"

def HeaderTokenVerification(header):
    if "Token" in header:
        token_status = check_token(header['Token'])
        if token_status == 'Ok':
            pass
        elif token_status == 'Expire':
            new_token = refresh_token(header['Token'])
            data_return = {
                "data":{"token":new_token},
                "message":"Token Expired",
                "code":"400",
                "error":{
                    "header":[{"params":"Token", "message":"Token Expired"}]
                }
            }
            return jsonify(data_return)
        else:
            data_return = {
                "data":None,
                "message":"Token {}".format(token_status),
                "code":"400",
                "error":{
                    "header":[{"params":"Token", "message":"Token {}".format(token_status)}]
                }
            }
            return jsonify(data_return)
    else:
        data_return = {
            "data":None,
            "message":"Token Not Found",
            "code":"400",
            "error":{
                "header":[{"params":"Token", "message":"Token Missing"}]
            }
        }
        return jsonify(data_return)


class Resource_Users(Resource):
    def get(self):
        # create_user = graph.run(" create (n:Users {Name:$Name}) ",Name="Alice")
        query_user = session.run("match (a:Users {Name:'Arik'})-[r1]->(b:Interactions)<-[r2]-(c) return a,b,c")
        data = []
        for i in query_user:
            d = {}
            # GET LABEL OF NODE
            # print(list(i.values()[0].labels)[0])
            node_data = i.data()
            d['InteractionID'] = node_data['b']['InteractionID']
            if list(i.values()[2].labels)[0] == "Places":
                d["Visit"] = {"Name":node_data['c']['Name']}
            else:
                d["Interaction"] = {"Name":node_data['c']['Name']}
            data.append(d)
        # print("createdr")
        return jsonify({"message":"HelloWolrd", "data":data})


api.add_resource(Resource_Users, '/api/users/')

if __name__ == "__main__":
	app.run(debug=True)