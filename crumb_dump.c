#define _GNU_SOURCE
#define _XOPEN_SOURCE 500
#include <errno.h>
#include <error.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/xattr.h>

static long max_depth = 0;

int printxattr(const char *path, const struct stat *stat, int type, struct FTW *ftw)
{
	ssize_t attr_len;
	char attr[PATH_MAX];

	if (ftw->level > max_depth) {
		return FTW_SKIP_SIBLINGS;
	}

	attr_len = lgetxattr(&path[ftw->base], "user.crumb-exe", attr, sizeof(attr));

	if (attr_len  >= 0) {
		printf("%s%c%.*s%c", path, '\0', (int) attr_len, attr, '\0');
	} else if (errno != ENODATA) {
		error(0, errno, "%s", path);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int opt, i;
	char *endptr;
	struct rlimit rlimit;

	while ((opt = getopt(argc, argv, "r::")) != -1) {
		switch (opt) {
		case 'r':
			max_depth = optarg ? strtol(optarg, &endptr, 10) : LONG_MAX;

			if (optarg && *endptr != '\0') {
				error(EXIT_FAILURE, 0, "invalid depth '%s'", optarg);
			}

			break;
		case '?':
			/* getopt prints an error message to stdout */
			return EXIT_FAILURE;
		}
	}

	if (getrlimit(RLIMIT_NOFILE, &rlimit) == -1) {
		error(EXIT_FAILURE, errno, "getrlimit");
	}

	for (i = optind; i < argc; ++i) {
		nftw(argv[i], printxattr, rlimit.rlim_cur / 2,
			FTW_PHYS | FTW_ACTIONRETVAL | FTW_CHDIR);
	}

	return error_message_count > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
