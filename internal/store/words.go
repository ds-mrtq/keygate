package store

// wordList is the fixed 256-word list used for fingerprints (8 bits per word). Never reorder.
var wordList = [256]string{
	"acid", "acorn", "adult", "agent", "alarm", "album", "alder", "alert",
	"almond", "alpine", "amber", "anchor", "angle", "apple", "apron", "arch",
	"arena", "arrow", "aspen", "atlas", "attic", "autumn", "avenue", "bacon",
	"badge", "bagel", "baker", "balsa", "bamboo", "banjo", "barn", "basil",
	"basket", "beach", "beacon", "bean", "berry", "birch", "bison", "blanket",
	"blaze", "bloom", "boat", "bonus", "border", "bottle", "branch", "bread",
	"brick", "bridge", "brook", "bubble", "bucket", "cabin", "cable", "cactus",
	"camel", "candle", "canoe", "canyon", "carbon", "cargo", "carpet", "castle",
	"cedar", "cellar", "chair", "chalk", "cherry", "chess", "chime", "cinder",
	"circle", "clover", "cobalt", "coffee", "comet", "copper", "coral", "cotton",
	"coyote", "crane", "crater", "cricket", "crown", "crystal", "curtain", "daisy",
	"dawn", "delta", "desert", "diamond", "dingo", "dolphin", "dragon", "drum",
	"eagle", "earth", "echo", "elbow", "ember", "engine", "falcon", "fennel",
	"fern", "ferry", "fiddle", "field", "finch", "flame", "flute", "forest",
	"fossil", "fox", "galaxy", "garden", "garlic", "geyser", "ginger", "glacier",
	"globe", "goose", "granite", "grape", "gravel", "grove", "guitar", "hammer",
	"harbor", "hazel", "heron", "hickory", "hollow", "honey", "horizon", "hornet",
	"island", "ivory", "jacket", "jasmine", "jaguar", "jelly", "jungle", "kayak",
	"kettle", "kiwi", "koala", "ladder", "lagoon", "lantern", "laurel", "lemon",
	"lilac", "lizard", "lobster", "lotus", "lunar", "magnet", "mango", "maple",
	"marble", "meadow", "melon", "mesa", "meteor", "mirror", "mist", "moose",
	"mosaic", "nectar", "needle", "nickel", "nutmeg", "oasis", "ocean", "olive",
	"onion", "orbit", "orchid", "otter", "oyster", "paddle", "palm", "panda",
	"paper", "peach", "pearl", "pepper", "pigeon", "pillow", "pine", "planet",
	"plum", "pocket", "polar", "pond", "poppy", "prairie", "pumpkin", "quail",
	"quartz", "quill", "rabbit", "radar", "raven", "reef", "ribbon", "river",
	"robin", "rocket", "saddle", "saffron", "salmon", "sand", "sapphire", "scarab",
	"shadow", "silver", "sketch", "sleet", "spark", "spruce", "squid", "star",
	"summit", "sunset", "swan", "thistle", "thunder", "tiger", "timber", "tulip",
	"tundra", "turtle", "valley", "velvet", "violet", "walnut", "willow", "window",
	"winter", "yarrow", "zebra", "zephyr", "bronze", "cider", "dune", "elm",
	"flint", "gecko", "hawk", "iris", "jade", "kelp", "lynx", "mint",
}

// WordList returns a copy of the fixed 256-word list (used by the PWA generator).
func WordList() [256]string { return wordList }
