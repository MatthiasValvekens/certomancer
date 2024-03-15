import os
import pathlib
import re
import shutil

TEST_DATA_PATH = pathlib.Path("tests", "data").absolute()


def collect_files(path):
    for cur, dirs, files in os.walk(str(path)):
        for file in files:
            yield os.path.relpath(os.path.join(cur, file), path)


def pytest_runtest_call(item):
    for marker in item.iter_markers():
        if marker.name == 'config_context':
            config_file = marker.args[0]
            for extra_config in (
                "external-arch.yml",
                "full-service-config.yml",
            ):
                shutil.copyfile(
                    str(TEST_DATA_PATH / extra_config), extra_config
                )
            with (TEST_DATA_PATH / config_file).open('r') as inf:
                with open("certomancer.yml", 'w') as outf:
                    pattern = re.compile(r"\s*path-prefix: keys-(.*)\n")
                    for line in inf:
                        m = pattern.fullmatch(line)
                        if m is not None:
                            keydir = pathlib.Path(f"keys-{m.group(1)}")
                            src_keydir = TEST_DATA_PATH / keydir
                            for keyfile in collect_files(src_keydir):
                                (keydir / keyfile).parent.mkdir(
                                    parents=True, exist_ok=True
                                )
                                shutil.copyfile(
                                    str(src_keydir / keyfile),
                                    str(keydir / keyfile),
                                )
                        outf.write(line)
