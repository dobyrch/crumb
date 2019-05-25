#define _XOPEN_SOURCE 500
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/xattr.h>

static int status = EXIT_SUCCESS;
static int recursive = 0, max_depth;

int printxattr(const char *path, const struct stat *stat, int type, struct FTW *ftw)
{
	ssize_t attr_len;
	char attr[PATH_MAX];


	attr_len = getxattr(path, "user.crumb-exe", attr, sizeof(attr));

	if (attr_len  >= 0) {
		printf("%s%c%.*s%c", path, '\0', (int)attr_len, attr, '\0');
	} else if (errno != ENODATA) {
		/* TODO: swap perror for null-terminated fprintf */
		perror("fgetxattr");
		fprintf(stderr, "%s\n", path);
		status = EXIT_FAILURE;
	}

	/* TODO: Stop when max depth exceeded */

	return 0;
}

int main(int argc, char **argv)
{
	int opt, i;
	struct rlimit rlimit;

	while ((opt = getopt(argc, argv, "r::")) != -1) {
		switch (opt) {
		case 'r':
			recursive = 1;
			max_depth = optarg ? atoi(optarg) : INT_MAX;
			break;
		case '?':
			/* getopt prints an error message to stdout */
			return EXIT_FAILURE;
		}
	}

	if (getrlimit(RLIMIT_NOFILE, &rlimit) == -1) {
		perror("getrlimit");
	}

	for (i = optind; i < argc; ++i) {
		/* TODO: WHY IS IT TRYING TO FOLLOW LINKS???? */
		nftw(argv[i], printxattr, rlimit.rlim_cur, FTW_PHYS);
	}

	return status;
}
