import yaml

def get_pseudonymsys_group():
    with open("../config/defaults.yml") as stream:
        try:
            data = yaml.load(stream)
            p = data["pseudonymsys"]["p"]
            q = data["pseudonymsys"]["q"]
            g = data["pseudonymsys"]["g"]
            return int(p), int(q), int(g)
        except yaml.YAMLError as exc:
            print(exc)
            
def get_pseudonymsys_user_secret():
    with open("../config/defaults.yml") as stream:
        try:
            data = yaml.load(stream)
            secret = data["pseudonymsys"]["user1"]["dlog"]["secret"]
            return int(secret)
        except yaml.YAMLError as exc:
            print(exc)
