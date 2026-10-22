from .code_signals import CodeSignalsCheck
from .dependencies import DependencyCheck
from .documentation import DocumentationCheck
from .install_dangers import InstallDangersCheck
from .security_signals import SecuritySignalsCheck

ALL_CHECKS = [
    DependencyCheck(),
    InstallDangersCheck(),
    DocumentationCheck(),
    CodeSignalsCheck(),
    SecuritySignalsCheck(),
]
