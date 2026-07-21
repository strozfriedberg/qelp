import time
import logging
from pathlib import Path
from collections import namedtuple
import re
from qelp.local_logger import logger
from qelp.support import ArchiveExtractor, Configure, Parser

LogIdentifier = namedtuple(
    "LogIdentifier", ["filename_start", "filename_pattern", "content_patterns"]
)
ContentPattern = namedtuple(
    "ContentPattern", ["regex", "access_types"]
)
AccessType = namedtuple(
    "AccessType", ["access_type_name", "description_handlers"]
)
DescriptionHandler = namedtuple(
    "DescriptionHandler", ["should_timeline", "regex"]
)  # this namedtuple is used to determine if a match should be added to the timeline based upon the Description content

LOG_IDENTIFIERS = [
    LogIdentifier(
        "hostd",
        r"^hostd\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z) (?P<Log_Level>\w+\(.*?\)|\w+) (?P<Event_ID>hostd\[\d{0,9}\])[: ](?P<Event_Type_ID>.*?)(?=:\s*)(:\s*(?P<Description>.*))"
                ),
                [
                    AccessType(
                        "Logon",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(Accepted password for user.*|User .*\@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} logged in.*|SSH session was opened.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ],
                    ),
                    AccessType(
                        "Logoff",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(User .*\@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} logged out.*|SSH session was closed.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ],
                    ),
                    AccessType(
                        "Failed-Logon",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(SSH login has failed.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ],
                    ),
                    AccessType(
                        "User_activity",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(SSH access has been.*|Account.* was created|Got HTTP.*|File upload to path.*|File download from path.*|The ESXi command line shell.*|file delete.*|Deletion of file or directory.*|DatastoreBrowserImpl::SearchInt.*dsPath:.*|Create requested for.*|Login password for user.* has been changed|Password was changed for account.*)",
                                re.IGNORECASE,
                                ),
                            ),
                            DescriptionHandler(
                                False,
                                re.compile(r"(Account.* was updated on host.*|Sent OK response for.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ],
                    )
                ],
            ),
        ],
    ),
    LogIdentifier(
        "syslog",
        r"^syslog\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z)( \w+\(.*?\) | )(?P<Logon_Type>sftp-server.*?|DCUI.*?)(?=:\s*)(:\s*(?P<Description>.*))"
                ),
                [
                     AccessType(
                        "Logon",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(r"User [a-zA-Z0-9].* logged in.*?"),
                            ),
                            DescriptionHandler(
                                False,
                                re.compile(r"(session opened.*)"),
                            ),
                        ],
                    ),
                     AccessType(
                        "Logoff",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(r"User [a-zA-Z0-9].* logged out.*?"),
                            ),
                            DescriptionHandler(
                                False,
                                re.compile(r"(session closed.*)"),
                            ),
                        ],
                    ),                    
                    AccessType(
                        "User_activity",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(r"password changed for.*|Login password for user.*"),
                            ),
                            DescriptionHandler(
                                False,
                                re.compile(
                                    r'(opendir.*|closedir.*|open ".*|close ".*|sent status.*)',
                                    re.IGNORECASE,
                                ),
                            ),
                        ],
                    )
                ]
            ),
        ],
    ),
    LogIdentifier(
        "shell",
        r"^shell\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z)( \w+\(.*?\) | )(?P<Logon_Type>[a-zA-Z].*?)(?=:\s*)(:\s*(?P<Description>.*))"
                ),
                [
                    AccessType(
                        "Bash_activity",
                        [
                            DescriptionHandler(True, re.compile(r".*")),
                        ],
                    )
                ]
            ),
        ],
    ),
    LogIdentifier(
        "auth",
        r"^auth\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z)( \w+\(.*?\) | )(?P<Logon_ID>\w+\[\d+\]):(?:.*?:)*\s*(?P<Description>.*)"
                ),
                [
                    AccessType(
                        "Logon",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(user [a-zA-Z0-9].* login.*|Accepted keyboard-interactive.*|Connection from.*|Session opened for.*)",
                                    re.IGNORECASE,
                                ),
                            ),
                        ]
                    ),

                    AccessType(
                        "Logoff",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(Session closed for.*|Connection closed by.*|Disconnected from.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ],
                    ),
                    AccessType(
                        "Failed-Logon",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(authentication failure;.*|error \[login.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ],
                    ),
                    AccessType(
                        "User_activity",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(password changed.*|User.* running command\s.*)",
                                    re.IGNORECASE,
                                ),
                            ),
                        ],
                    )
                ]
            ),
        ],
    ),
    LogIdentifier(
        "vmauthd",
        r"^vmauthd\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z)( \w+\(.*?\) | |: )(?P<Logon_ID>vmauthd.*?)(?=:\s*)(:\s*(?P<Description>.*))"
                ),
                [
                    AccessType(
                        "Remote_access",
                        [
                            DescriptionHandler(
                                False,
                                re.compile(r"(Connect from remote socket.*)"),
                            ),
                        ],
                    )
                ]
            ),
        ],
    ),
    LogIdentifier(
        "vmkernel",
        r"^vmkernel\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)\b(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z)\b.*?(?P<Description>(Accepted connection from.*|Error reading from pending connection:.*))\b"
                ),
                [
                    AccessType(
                        "Remote_access",
                        [
                            DescriptionHandler(False, re.compile(r".*")),
                        ],
                    ),
                    AccessType(
                        "Execution_denied",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(r"(.*sh: exec denied.*)"),
                            ),
                        ],
                    )
                ]
            ),
        ],
    ),
    LogIdentifier(
        "vobd",
        r"^vobd\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z)( \w+\(.*?\) vobd\[.*?\]:  |: )(?P<Type>\[.*?\]) (?P<ID>\d+.*?)(?=:\s*)(:\s*(?P<Description_Type>\[.*?\])) (?P<Description>.*)"
                ),
                [
                    AccessType(
                        "Logon",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(SSH session was opened.*|Authentication of user.* has.*)",
                                re.IGNORECASE,
                                ),
                                
                            ),
                        ],
                    ),
                    AccessType(
                        "Logoff",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(SSH session was closed.*|Authentication of user.* has.*)",
                                re.IGNORECASE,
                                ),
                                
                            ),
                        ],
                    ),
                    AccessType(
                        "User_activity",
                        [
                            DescriptionHandler(
                                True,
                                re.compile(
                                    r"(The ESX command line shell has been.*|Administrator access to the host has been.*|Login password for user.*|SSH access has been.*)",
                                re.IGNORECASE,
                                ),
                            ),
                        ]
                    )
                ],
            ),
        ],
    ),
    LogIdentifier(
        "esxcli",
        r"^esxcli\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z) (?P<Log_Level>\w+\(.*?\)|\w+|\w+\(.*?\)\[.*?\]|esxcli:\s+\w+\s+\[\d+\]) (esxcli\[.*?\]: |esxcli\[.*?\] |esxcli\[.*?\]:\s\s|)(?P<Type>[^:]+|\w+\s+\w+):\s*(?P<Description>.*)"
                ),
                [
                    AccessType(
                        "User_activity",
                        [
                            DescriptionHandler(True, re.compile(r".*")),
                        ],
                    ),
                ]
            ),
        ],
    ),
    LogIdentifier(
        "rhttpproxy",
        r"^rhttpproxy\.(log|\d+.gz|log\..*?)$",
        [
            ContentPattern(
                re.compile(
                    r"(?i)(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*?Z) (?P<Log_Level>\w+) (?P<Log_ID>rhttpproxy\[\d+\]) (?P<Description_Type>\[.*?\]) (?P<Description>.*)"
                ),
                [
                    AccessType(
                        "Remote_access",
                        [
                            DescriptionHandler(
                                False,
                                re.compile(r"(New proxy client.*)"),
                            ),
                        ],
                    )
                ]
            ),
        ],
    ),
]


def check_extract_and_parse_archives(
    archive_source: Path, result_destination: Path
) -> None:
    archive_extractor = ArchiveExtractor(LOG_IDENTIFIERS)
    for dir_path, _dir_names, file_names in archive_source.walk():
        for file_name in file_names:
            archive_path = dir_path / file_name
            if extraction_dir := archive_extractor.extract_archive(
                archive_path, result_destination
            ):
                parser = Parser(extraction_dir, LOG_IDENTIFIERS)
                parser.read_parse_logs()


def main():
    try:
        configure = Configure()
    except NotADirectoryError as e:
        print(e)
        return

    start_time = time.time()
    check_extract_and_parse_archives(configure.input_dir, configure.output_dir)
    finish_time = time.time()

    elapsed_time = finish_time - start_time
    logger.info("ESXi triage completed in %s seconds", int(elapsed_time))


if __name__ == "__main__":
    main()
