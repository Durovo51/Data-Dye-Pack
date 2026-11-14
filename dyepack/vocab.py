"""The recipe for a customer row.

A row is built from parts (names, street, city, plan and so on). The lab makes
customers from this recipe, canaries come from it and the honey lock encodes
parts, so real rows and fakes always look alike.
"""


def _ranked(names):
    # rough popularity: earlier names show up more often
    return {n: round(1000 / (i + 8)) for i, n in enumerate(names)}


FIRST_NAMES = _ranked((
    "James", "Mary", "Michael", "Patricia", "John", "Jennifer", "Robert", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Karen", "Christopher", "Sarah", "Charles", "Lisa", "Daniel", "Nancy",
    "Matthew", "Sandra", "Anthony", "Ashley", "Mark", "Emily", "Steven", "Donna",
    "Andrew", "Michelle", "Joshua", "Carol", "Kevin", "Amanda", "Brian", "Melissa",
    "Ryan", "Deborah", "Jacob", "Stephanie", "Nicholas", "Rebecca", "Eric", "Laura",
    "Jonathan", "Hannah", "Justin", "Megan", "Brandon", "Rachel", "Tyler", "Olivia",
    "Samuel", "Emma", "Benjamin", "Sophia", "Nathan", "Abigail", "Zachary", "Madison",
    "Ethan", "Grace", "Logan", "Chloe", "Noah", "Ava", "Lucas", "Mia",
    "Mason", "Ella", "Liam", "Lily", "Owen", "Natalie", "Caleb", "Hailey",
    "Wyatt", "Brooke", "Isaac", "Allison", "Gavin", "Paige", "Connor", "Morgan",
    "Hunter", "Kayla", "Carter", "Jenna", "Dylan", "Claire", "Evan", "Sydney",
    "Raj", "Priya", "Wei", "Mei", "Carlos", "Maria", "Luis", "Ana",
))

LAST_NAMES = _ranked((
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Garcia",
    "Rodriguez", "Wilson", "Martinez", "Anderson", "Taylor", "Thomas", "Hernandez", "Moore",
    "Martin", "Jackson", "Thompson", "White", "Lopez", "Lee", "Gonzalez", "Harris",
    "Clark", "Lewis", "Robinson", "Walker", "Perez", "Hall", "Young", "Allen",
    "Sanchez", "Wright", "King", "Scott", "Green", "Baker", "Adams", "Nelson",
    "Hill", "Ramirez", "Campbell", "Mitchell", "Roberts", "Carter", "Phillips", "Evans",
    "Turner", "Torres", "Parker", "Collins", "Edwards", "Stewart", "Morris", "Nguyen",
    "Murphy", "Rivera", "Cook", "Rogers", "Morgan", "Peterson", "Cooper", "Reed",
    "Bailey", "Bell", "Gomez", "Kelly", "Howard", "Ward", "Cox", "Diaz",
    "Richardson", "Wood", "Watson", "Brooks", "Bennett", "Gray", "Hughes", "Price",
    "Olson", "Schmidt", "Mueller", "Larson", "Hanson", "Schultz", "Krueger", "Becker",
    "Weber", "Hoffman", "Wagner", "Kowalski", "Patel", "Shah", "Chen", "Wang",
    "Kim", "Singh", "Foster", "Sullivan", "Russell", "Jenkins", "Fisher", "Henderson",
))

STREET_NAMES = _ranked((
    "Main", "Oak", "Maple", "Park", "Cedar", "Elm", "Washington", "Lake",
    "Pine", "Hill", "Willow", "University", "Johnson", "Jefferson", "Lincoln", "Madison",
    "Monroe", "Spring", "Prairie", "Meadow", "Sunset", "River", "Forest", "Ridge",
    "Valley", "Highland", "Orchard", "Mill", "Church", "School", "Center", "Franklin",
    "Chestnut", "Walnut", "Hickory", "Aspen", "Spruce", "Lakeview", "Fox", "Deer",
    "Heather", "Juniper", "Cherry", "Garden", "Grove", "Bluff", "Harbor", "Regent",
    "Mineral Point", "Old Sauk",
))

STREET_TYPES = {"St": 30, "Ave": 20, "Rd": 15, "Dr": 12, "Ln": 10, "Ct": 6, "Way": 4, "Pl": 3}

# city: (weight, area code, zip codes)
CITIES = {
    "Madison": (40, "608", ("53703", "53704", "53705", "53711", "53713", "53714",
                            "53715", "53716", "53717", "53718", "53719")),
    "Middleton": (6, "608", ("53562",)),
    "Sun Prairie": (6, "608", ("53590",)),
    "Fitchburg": (5, "608", ("53711", "53719")),
    "Verona": (3, "608", ("53593",)),
    "Waunakee": (3, "608", ("53597",)),
    "Stoughton": (3, "608", ("53589",)),
    "Monona": (2, "608", ("53716",)),
    "McFarland": (2, "608", ("53558",)),
    "DeForest": (2, "608", ("53532",)),
    "Oregon": (2, "608", ("53575",)),
    "Mount Horeb": (2, "608", ("53572",)),
    "Cottage Grove": (2, "608", ("53527",)),
    "Janesville": (6, "608", ("53545", "53546", "53548")),
    "Beloit": (4, "608", ("53511",)),
    "Baraboo": (2, "608", ("53913",)),
    "Portage": (2, "608", ("53901",)),
    "Sauk City": (1, "608", ("53583",)),
    "Dodgeville": (1, "608", ("53533",)),
    "Platteville": (2, "608", ("53818",)),
    "La Crosse": (5, "608", ("54601", "54603")),
    "Eau Claire": (5, "715", ("54701", "54703")),
    "Wausau": (4, "715", ("54401", "54403")),
    "Stevens Point": (3, "715", ("54481",)),
    "Green Bay": (7, "920", ("54301", "54302", "54303", "54304")),
    "Appleton": (6, "920", ("54911", "54913", "54914")),
    "Oshkosh": (5, "920", ("54901", "54902", "54904")),
    "Fond du Lac": (3, "920", ("54935", "54937")),
    "Sheboygan": (3, "920", ("53081", "53083")),
    "Waukesha": (6, "262", ("53186", "53188", "53189")),
    "Kenosha": (5, "262", ("53140", "53142", "53143", "53144")),
    "Racine": (5, "262", ("53402", "53403", "53404", "53405")),
    "West Bend": (2, "262", ("53090", "53095")),
}

# plan: (monthly price, weight). Lakeview Fiber is made up
PLANS = {
    "Fiber 300": (55.00, 22),
    "Fiber 500": (65.00, 25),
    "Fiber 1 Gig": (80.00, 20),
    "Fiber 2 Gig": (110.00, 6),
    "Cable 200": (49.99, 12),
    "Cable 600": (69.99, 10),
    "DSL 25": (39.99, 5),
}

# add on: (monthly price, weight). prices differ so the bill tells them apart
ADDONS = {
    "none": (0.00, 55),
    "Wi-Fi extender": (10.00, 20),
    "Static IP": (15.00, 5),
    "Phone line": (20.00, 8),
    "TV Basic": (25.00, 12),
}

EMAIL_DOMAINS = {
    "gmail.com": 45, "yahoo.com": 12, "icloud.com": 10, "outlook.com": 8,
    "hotmail.com": 7, "lakeviewfiber.net": 10, "aol.com": 3, "att.net": 3,
}
EMAIL_STYLES = {"first.last": 40, "flast": 35, "firstl": 25}
USER_STYLES = {"flast": 50, "first": 25, "first.l": 25}
SINCE_YEARS = {str(y): y - 2004 for y in range(2008, 2027)}

# parts in encode order. "cat" picks from a weighted list, ("int", lo, hi) is a
# plain number range and "zip" picks one of the zips of the city chosen before it
PARTS = (
    ("first_name", "cat"),
    ("last_name", "cat"),
    ("house_no", ("int", 1, 9999)),
    ("street_name", "cat"),
    ("street_type", "cat"),
    ("city", "cat"),
    ("zip_idx", "zip"),
    ("exchange", ("int", 200, 999)),
    ("line", ("int", 0, 9999)),
    ("email_style", "cat"),
    ("email_dd", ("int", 0, 99)),
    ("email_domain", "cat"),
    ("plan", "cat"),
    ("addon", "cat"),
    ("since_year", "cat"),
    ("account", ("int", 0, 99_999_999)),
    ("user_style", "cat"),
    ("user_dd", ("int", 0, 9999)),  # 4 digits so common names don't run out of logins
)

# default weights for every "cat" part (a profile from a real table replaces these)
CATEGORIES = {
    "first_name": FIRST_NAMES,
    "last_name": LAST_NAMES,
    "street_name": STREET_NAMES,
    "street_type": STREET_TYPES,
    "city": {c: w for c, (w, _, _) in CITIES.items()},
    "email_style": EMAIL_STYLES,
    "email_domain": EMAIL_DOMAINS,
    "plan": {p: w for p, (_, w) in PLANS.items()},
    "addon": {a: w for a, (_, w) in ADDONS.items()},
    "since_year": SINCE_YEARS,
    "user_style": USER_STYLES,
}


def zips_for(city):
    return CITIES[city][2]


def _email_local(style, first, last):
    f, l = first.lower(), last.lower()
    return {"first.last": f"{f}.{l}", "flast": f"{f[0]}{l}", "firstl": f"{f}{l[0]}"}[style]


def _user_base(style, first, last):
    f, l = first.lower(), last.lower()
    return {"flast": f"{f[0]}{l}", "first": f, "first.l": f"{f}.{l[0]}"}[style]


def compose(p):
    """Parts dict -> customer row dict (keys match schema.CUSTOMER_FIELDS)."""
    first, last, city = p["first_name"], p["last_name"], p["city"]
    area, zips = CITIES[city][1], CITIES[city][2]
    bill = PLANS[p["plan"]][0] + ADDONS[p["addon"]][0]
    return {
        "account_no": f"LV{p['account']:08d}",
        "first_name": first,
        "last_name": last,
        "street": f"{p['house_no']} {p['street_name']} {p['street_type']}",
        "city": city,
        "zip": zips[p["zip_idx"]],
        "phone": f"{area}-{p['exchange']:03d}-{p['line']:04d}",
        "email": f"{_email_local(p['email_style'], first, last)}{p['email_dd']:02d}@{p['email_domain']}",
        "plan": p["plan"],
        "monthly_bill": round(bill, 2),
        "since_year": int(p["since_year"]),
        "portal_user": f"{_user_base(p['user_style'], first, last)}{p['user_dd']:04d}",
    }


def _same(a, b):
    return all(
        abs(a[k] - b[k]) < 0.005 if k == "monthly_bill" else a[k] == b[k]
        for k in a
    )


def decompose(row):
    """Customer row -> parts dict. Raises ValueError if the row doesn't fit the recipe."""
    try:
        # rows from CSV or JSON files carry numbers as text
        row = dict(row, monthly_bill=round(float(row["monthly_bill"]), 2),
                   since_year=int(row["since_year"]))
        first, last, city, plan = row["first_name"], row["last_name"], row["city"], row["plan"]
        tokens = row["street"].split(" ")
        area, exchange, line = row["phone"].split("-")
        local, domain = row["email"].split("@")
        addon_price = round(float(row["monthly_bill"]) - PLANS[plan][0], 2)
        addon = next(a for a, (price, _) in ADDONS.items() if abs(price - addon_price) < 0.005)
        email_style = next(s for s in EMAIL_STYLES if _email_local(s, first, last) == local[:-2])
        user = row["portal_user"]
        user_style = next(s for s in USER_STYLES if _user_base(s, first, last) == user[:-4])
        p = {
            "first_name": first,
            "last_name": last,
            "house_no": int(tokens[0]),
            "street_name": " ".join(tokens[1:-1]),
            "street_type": tokens[-1],
            "city": city,
            "zip_idx": zips_for(city).index(row["zip"]),
            "exchange": int(exchange),
            "line": int(line),
            "email_style": email_style,
            "email_dd": int(local[-2:]),
            "email_domain": domain,
            "plan": plan,
            "addon": addon,
            "since_year": str(row["since_year"]),
            "account": int(row["account_no"][2:]),
            "user_style": user_style,
            "user_dd": int(user[-4:]),
        }
    except (KeyError, ValueError, StopIteration, IndexError) as e:
        raise ValueError(f"row doesn't fit the recipe: {row.get('account_no')}") from e
    if CITIES[city][1] != area or not _same(compose(p), row):
        raise ValueError(f"row doesn't fit the recipe: {row.get('account_no')}")
    return p
