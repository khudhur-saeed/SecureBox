import math
import secrets 
import string
from typing import List, Optional, Tuple

DEFAULT_WORDLIST: List[str] = [
    "ability", "absent", "absorb", "abstract", "academy", "accent", "account", "acid",
    "acoustic", "acquire", "across", "action", "active", "actor", "adapt", "address",
    "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "agent",
    "agree", "ahead", "airport", "alarm", "album", "alert", "alien", "allied",
    "alpha", "alter", "always", "amber", "amuse", "anchor", "ancient", "angel",
    "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another",
    "answer", "antenna", "antique", "anxiety", "anyway", "apart", "apology", "appear",
    "apple", "approve", "apron", "arcade", "arch", "arctic", "arena", "argon",
    "armor", "arrow", "artist", "aspect", "assault", "asset", "assist", "assume",
    "atomic", "attach", "attack", "attend", "attitude", "attract", "auction", "audit",
    "august", "aunt", "author", "auto", "autumn", "avatar", "avenue", "average",
    "avocado", "avoid", "awake", "aware", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "bargain", "barrel", "barrier", "base",
    "basic", "basket", "battle", "beach", "beacon", "beam", "bean", "beauty",
    "because", "become", "beef", "before", "begin", "behave", "behind", "belief",
    "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
    "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board",
    "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border",
    "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket",
    "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge",
    "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal"
]

AMBIGUOUS_CHARS = "il1Lo0O"

def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
)-> str:
    """Generates a cryptographically secure random password using secrets (CSPRNG)."""
    if length < 8 :
        raise ValueError("Password length must be at least 8 characters.")
    
    char_pool = ""
    guaranteed_chars = [] 

    if use_lower:
        pool = string.ascii_lowercase
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool
        guaranteed_chars.append(secrets.choice(pool))

    if use_upper:
        pool = string.ascii_uppercase
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool
        guaranteed_chars.append(secrets.choice(pool))

    if use_digits:
        pool = string.digits
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool
        guaranteed_chars.append(secrets.choice(pool))

    if use_symbols:
        pool = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if avoid_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        char_pool += pool
        guaranteed_chars.append(secrets.choice(pool))

    if not char_pool:
        raise ValueError("At least one character set must be selected.")

    remaining_length = length - len(guaranteed_chars)
    password_chars = guaranteed_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]

    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)

def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    wordlist: Optional[List[str]] = None,
) -> str:
    """Generates a secure, human-friendly passphrase using CSPRNG word selection."""
    if num_words < 3:
        raise ValueError("Passphrase should contain at least 3 words.")
    
    words = wordlist or DEFAULT_WORDLIST
    selected_words = [secrets.choice(words) for _ in range(num_words)]

    selected_words = [secrets.choice(words) for _ in range(num_words)]

    if capitalize:
        selected_words = [w.capitalize() for w in selected_words]

    return separator.join(selected_words)

def calculate_entropy(password:str) -> Tuple[float, str]:
    """Calculates Shannon entropy in bits and returns an evaluation label."""
    if not password:
        return 0.0, "Empty"

    pool_size = 0
    if any (c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any (c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any (c in string.digits for c in password):
        pool_size += 10 
    if any (c in "!@#$%^&*()-_=+[]{}|;:,.<>?`~'\"/\\" for c in password):
        pool_size += 33

    if pool_size == 0:
        pool_size = 256

    entropy = len(password) * math.log2(pool_size)

    entropy = len(password) * math.log2(pool_size)

    if entropy < 40:
        rating = "[bold red]Very Weak[/bold red]"
    elif entropy < 60:
        rating = "[bold yellow]Weak[/bold yellow]"
    elif entropy < 80:
        rating = "[bold cyan]Good[/bold cyan]"
    elif entropy < 100:
        rating = "[bold green]Strong[/bold green]"
    else:
        rating = "[bold magenta]Extremely Strong[/bold magenta]"

    return round(entropy, 2), rating
