import abc
import datetime
import os
import pathlib
import platform
import re
import sys
import typing
import glob

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))


import ccl_chromium_snss2
import subprocess

sys.stdout.reconfigure(encoding="utf-8")


WINDOWS = False

CHROME_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0)


class AbstractAuditor(abc.ABC):
    def __init__(self, name: str):
        self.name = name

    @property
    @abc.abstractmethod
    def headers(self) -> tuple[str, ...]:
        raise NotImplementedError

    @abc.abstractmethod
    def audit(
        self,
        profile_root: typing.Union[os.PathLike, str],
        domain_re: re.Pattern,
    ) -> typing.Iterator[tuple]:
        raise NotImplementedError


class SnssAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Snss")

    @property
    def headers(self) -> tuple[str, ...]:
        return (
            "file",
            "offset",
            "index",
            "timestamp",
            "title",
            "url",
            "original_request_url",
            "referrer_url",
        )

    def audit(
        self,
        profile_root: typing.Union[os.PathLike, str],
        domain_re: re.Pattern,
    ) -> typing.Iterator[tuple]:
        session_folder = pathlib.Path(profile_root) / "Sessions"
        if not session_folder.exists():
            return
        for snss_file in session_folder.iterdir():
            if not snss_file.is_file():
                continue
            if not (
                snss_file.name.startswith("Session_")
                or snss_file.name.startswith("Tabs_")
            ):
                continue

            with snss_file.open("rb") as f:
                snss = ccl_chromium_snss2.SnssFile(
                    ccl_chromium_snss2.SnssFileType.Session
                    if snss_file.name.startswith("Session_")
                    else ccl_chromium_snss2.SnssFileType.Tab,
                    f,
                )
                for navigation_entry in snss.iter_session_commands():
                    if not isinstance(
                        navigation_entry, ccl_chromium_snss2.NavigationEntry
                    ):
                        continue  # TODO: There may well be other useful session commands to look into later

                    # TODO: add PageState stuff once it's in place in ccl_chromium_snss2
                    yield (
                        snss_file.name,
                        navigation_entry.offset,
                        navigation_entry.index,
                        navigation_entry.timestamp,
                        navigation_entry.title,
                        navigation_entry.url,
                        navigation_entry.original_request_url,
                        navigation_entry.referrer_url,
                    )


def main():
    WINDOWS = platform.system() == "Windows"
    if WINDOWS:
        pattern = ".*"
        domain_re = re.compile(pattern)
        username = os.getlogin()
        most_recent_path = glob.glob(
            f"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Sessions\\Session*"
        )
        most_recent_path.sort(key=os.path.getmtime, reverse=True)
        most_recent = most_recent_path[0].split("\\")
        profile_folder = pathlib.Path(
            f"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
        )
    else:
        domain_re = re.compile("$HOME/.config/google-chrome/Default")
        most_recent_path = glob.glob(
            "$HOME/.config/google-chrome/Default/Sessions/Session*"
        )
        most_recent_path.sort(key=os.path.getmtime, reverse=True)
        most_recent = most_recent_path[0].split("/")
        profile_folder = pathlib.Path("$HOME/.config/google-chrome/Default")

    # Keep track of seen URLs
    seen_titles = []
    seen_urls = []

    auditor = SnssAuditor()
    print("-" * 72)
    print(auditor.name)
    print("-" * 72)
    print("\t".join(auditor.headers))

    results = auditor.audit(profile_folder, domain_re)

    try:
        # Get first result
        result = next(results)
        next_result = next(results)
        while True:
            text = "\t".join(str(x) for x in result)

            # For session data, use URL (index 5) as unique identifier
            if most_recent[len(most_recent) - 1] in text:
                title = result[4] if len(result) > 4 else text
                url = result[5]
                if (
                    result[2] > next_result[2] + 1
                    or next_result is None
                    or result[2] == next_result[2]
                ):
                    if title not in seen_titles and url not in seen_urls:
                        if "www.youtube.com/watch?v=" in url:
                            print(text)
                            # Pass URL as a positional argument and options as kwargs
                            # Run the you-get command as a shell command
                            if input("Download video? (y/n): ") == "y":
                                subprocess.run(
                                    ["you-get", "--itag=18", url], check=False
                                )
                        seen_titles.append(title)
                        seen_urls.append(url)
            # Get next result
            result = next_result
            next_result = next(results)

    except StopIteration:
        pass


if __name__ == "__main__":
    main()
