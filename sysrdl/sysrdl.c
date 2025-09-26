#include "prototype.h"
#include "crypto.h"
#include "RDL.h"

int main(int argc, char* argv[]) {

    parse_args(argc, argv);
    RDL();

    return 0;
}