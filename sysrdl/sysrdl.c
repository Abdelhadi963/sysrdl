#include "prototype.h"
#include "crypto.h"
#include "RDL.h"

int main(int argc, char* argv[]) {
    /*if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return 1;
    }

   BuildDllPath(argv[1]);*/
    parse_args(argc, argv);
    RDL();

    return 0;
}