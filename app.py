from flask import Flask, jsonify, abort, request, make_response, render_template
from flask_restful import Api, Resource, reqparse
from neo4j import GraphDatabase, basic_auth
import datetime, time, uuid
import jwt

# Graph DB Connection
graph_user = "neo4j"
graph_password = "0oIXkYwWMhaEfmccsTTQJeMz3nHScaPbrE451Cq28k0"
graph_url = "neo4j+s://a0e76398.databases.neo4j.io:7687"

driver = GraphDatabase.driver(graph_url, auth=basic_auth(graph_user, graph_password))
session = driver.session()

app = Flask(__name__)
api = Api(app)

# App Config
app.config["SECRET_KEY"] = "ThisisVerySecret"

@app.route('/')
def index():
    return render_template('docs.html')

# JWT
class AuthHandler():
    secret = app.config['SECRET_KEY']
    # GenerateEncodeToken
    def encode_token(self, userid, type):
        payload = {
            "iss":userid,
            "type":type
        }
        if type == "access_token":
            payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        else:
            payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=720)

        jwt_token = jwt.encode(payload, self.secret, algorithm="HS256")
        return jwt_token

    # Create Token
    def encode_login_token(self, userid):
        access_token = self.encode_token(userid, "access_token")
        refresh_token = self.encode_token(userid, "refresh_token")

        login_token = {
            "access_token":access_token,
            "refresh_token":refresh_token
        }
        return login_token

    def encode_update_token(self, userid):
        access_token = self.encode_token(userid, "access_token")

        update_token = dict(
            access_token=f"{access_token}"
        ) 
        return update_token

    # Decode Token
    def decode_access_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            if payload['type'] != "access_token":
                data_return = {
                    "data":None,
                    "message":"Token Invalid",
                    "code":"401",
                    "error":{
                        "header":[{"params":"Token", "message":"Token Invalid"}]
                    }
                }
                response = make_response(data_return,401)
                return abort(response)
            return payload['iss']
        except jwt.ExpiredSignatureError:
            data_return = {
                "data":None,
                "message":"Token Expired",
                "code":"401",
                "error":{
                    "header":[{"params":"Token", "message":"Token Expired"}]
                }
            }
            response = make_response(data_return,401)
            return abort(response)
        except jwt.InvalidTokenError as e:
            data_return = {
                "data":None,
                "message":"Token Invalid",
                "code":"401",
                "error":{
                    "header":[{"params":"Token", "message":"Token Invalid"}]
                }
            }
            response = make_response(data_return,401)
            return abort(response)

    # Decode Token
    def decode_refresh_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            if payload['type'] != "refresh_token":
                data_return = {
                    "data":None,
                    "message":"Token Invalid",
                    "code":"401",
                    "error":{
                        "header":[{"params":"Token", "message":"Token Invalid"}]
                    }
                }
                response = make_response(data_return,401)
                return abort(response)
            return payload['iss']
        except jwt.ExpiredSignatureError:
            data_return = {
                "data":None,
                "message":"Token Expired",
                "code":"401",
                "error":{
                    "header":[{"params":"Token", "message":"Token Expired"}]
                }
            }
            response = make_response(data_return,401)
            return abort(response)
        except jwt.InvalidTokenError as e:
            data_return = {
                "data":None,
                "message":"Token Invalid",
                "code":"401",
                "error":{
                    "header":[{"params":"Token", "message":"Token Invalid"}]
                }
            }
            response = make_response(data_return,401)
            return abort(response)

    # Check access Token
    def auth_access_wrapper(self, token):
        return self.decode_access_token(token)

    # Check refresh Token
    def auth_refresh_wrapper(self, token):
        return self.decode_refresh_token(token)

# initiate AuthHandler
auth_handler=AuthHandler()

class Resource_Users(Resource):
    def get(self):
        # Initiate args
        parser = reqparse.RequestParser()
        parser.add_argument('NIK',location='args',type=int)
        args = parser.parse_args()

        # Check if "NIK" in args
        if args['NIK']:
            query_user = session.run("match (a:Users {NIK:$NIK}) return a ",NIK=int(args['NIK']))
            query_user = query_user.single()
            if query_user == None:
                return jsonify({"code":"200","data":None,"error":None,"message":"Get User by NIK Success"})
            else:
                query_user = query_user.data()['a']
                return jsonify({"code":"200","data":query_user,"error":None,"message":"Get User by NIK Success"})
        else:
            query_user = session.run("match (a:Users ) return a ")
            data_user = []
            for i in query_user:
                data = i.data()['a']
                data_user.append(data)
            return jsonify({"code":"200","data":data_user,"error":None,"message":"Get User Success"})

class Resource_Interactions(Resource):
    def get(self):
        # Get Parameters from headers
        header = dict(request.headers)
        # Check if "Token" in headers
        if "Token" not in header:
            data_return = {
                "data":None,
                "message":"Token Not Found",
                "code":"400",
                "error":{
                    "header":[{"params":"Token", "message":"Token Missing"}]
                }
            }
            return jsonify(data_return)
        # Get Token from headers
        token = header['Token']
        # Validate Token
        auth = auth_handler.auth_access_wrapper(token)
        query_user = session.run("match (a:Users {UserID:$UserID})-[r1]->(b:Interactions)<-[r2]-(c) return a,b,c",UserID=auth)
        data = []
        for i in query_user:
            # GET LABEL OF NODE
            # print(list(i.values()[0].labels)[0])
            node_data = i.data()
            d = node_data['b']
            if list(i.values()[2].labels)[0] == "Places":
                d["Visit"] = node_data['c']
            else:
                d["Interaction"] = node_data['c']
            data.append(d)
        return jsonify({"code":"200","data":data,"error":None,"message":"Get Interactions Success"})

class Resource_Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("Email", location="form")
        parser.add_argument("Password", location="form")
        args = parser.parse_args()

        # List for error message
        error_message = []

        if args['Email'] == None or args['Password'] == None:
            if args['Email'] == None:
                error = {"params":"Email","message":"Email Missing"}
                error_message.append(error)

            if args['Password'] == None:
                error = {"params":"Password","message":"Password Missing"}
                error_message.append(error)

            data_return = {
                "data":None,
                "message":"Login Failed",
                "code":"400",
                "error":{
                    "params":error_message
                }
            }

            return jsonify(data_return)

        cek_user = session.run('match (n:Users) where n.Email =$Email AND n.Password=$Password return n',Email=args['Email'],Password=args['Password'])
        cek_user = cek_user.single()
        if cek_user != None:
            # set Token 
            data = cek_user.data()['n']
            Token = auth_handler.encode_login_token(data['UserID'])
            data_return = {
                "data":{"Token":Token,"User":data},
                "message":"Login Success",
                "code":"200",
                "error":None
            }
            return jsonify(data_return)
        else:
            data_return = {
                "data":None,
                "message":"Login Failed. Email or Password Wrong",
                "code":"400",
                "error":{
                    "params":error_message
                }
            }
            return jsonify(data_return)

class Resource_Refresh_Token(Resource):
    def get(self):
        # Get Parameters from headers
        header = dict(request.headers)
        # Check if "Token" in headers
        if "Token" not in header:
            data_return = {
                "data":None,
                "message":"Token Not Found",
                "code":"400",
                "error":{
                    "header":[{"params":"Token", "message":"Token Missing"}]
                }
            }
            return jsonify(data_return)
        # Get Token from headers
        token = header['Token']
        # Validate Token
        auth = auth_handler.auth_refresh_wrapper(token)
        # Generate new_token
        New_Token = auth_handler.encode_login_token(auth)
        data_return = {
            "data":{"Token":New_Token},
            "message":"Refresh Token Success",
            "code":"200",
            "error":None
        }
        return jsonify(data_return)

class Resource_Scan(Resource):
    def get(self):
        # Get Parameters from headers
        header = dict(request.headers)
        # Check if "Token" in headers
        if "Token" not in header:
            data_return = {
                "data":None,
                "message":"Token Not Found",
                "code":"400",
                "error":{
                    "header":[{"params":"Token", "message":"Token Missing"}]
                }
            }
            return jsonify(data_return)
        # Get Token from headers
        token = header['Token']
        # Validate Token
        auth = auth_handler.auth_access_wrapper(token)

        parser = reqparse.RequestParser()
        parser.add_argument('NIK', required= True, location='form') #lawan bicara, #didapat dari scan QRcode
        parser.add_argument('lat', required= True, location='form')
        parser.add_argument('lng', required= True, location='form')
        args = parser.parse_args()

        # check if Nik exists
        query_user = session.run("match (a:Users {NIK:$NIK}) return a ",NIK=int(args['NIK']))
        query_user = query_user.single()
        if query_user == None:
            return jsonify({"code":"404","data":None,"error":None,"message":"Scan Failed. User by NIK:{} not Found".format(args['NIK'])})
        query_user = query_user.data()['a']
        
        # Generate InteractionID
        InteractionID = str(uuid.uuid4())
        # Generate Timestamp
        datetime_sql = time.time()
        # Format Timestamp to string
        datetime_print = datetime.datetime.fromtimestamp(datetime_sql).strftime('%Y-%m-%d %H:%M:%S')
        
        # Create Interaction Node
        interaction = session.run(" create(a:Interactions {InteractionID:$InteractionID,datetime_print:$datetime_print,datetime_sql:$datetime_sql,lat:$lat,lng:$lng}) ",InteractionID=InteractionID,datetime_print=datetime_print,datetime_sql=datetime_sql,lat=args['lat'] ,lng=args['lng'])

        # Connect User
        person1 = session.run("match (a:Users {UserID:$UserID}),(b:Interactions {InteractionID:$InteractionID}) merge (a)-[:MEET]->(b)  ",UserID=auth,InteractionID=InteractionID)

        # Connect User
        person2 = session.run(" match(a:Users {UserID:$UserID}),(b:Interactions {InteractionID:$InteractionID}) merge (a)-[:MEET]->(b) ",UserID=query_user["UserID"],InteractionID=InteractionID)
        
        data_return = {
            "data": None,
            "message":"Interaction Created",
            "code": "200",
            "error":None
        }
        return jsonify(data_return)

# class Resource_coba(Resource):
#     def get(self):
#         token = dict(request.headers)['Token']
#         tes = auth_handler.auth_access_wrapper(token)
#         print(tes)
#         return jsonify({"message":"Success"})

api.add_resource(Resource_Users, '/api/users/')
api.add_resource(Resource_Interactions, "/api/interactions/")
api.add_resource(Resource_Login, "/api/login/")
api.add_resource(Resource_Refresh_Token, "/api/refresh_token/")
api.add_resource(Resource_Scan, "/api/scan/")
# api.add_resource(Resource_coba, "/api/coba/")

if __name__ == "__main__":
	app.run(debug=True)