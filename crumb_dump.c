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

#define USAGE "\nUsage: %s [-r[DEPTH]] FILE..."

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
	int opt, i, ret;
	char *endptr;
	struct rlimit rlimit;

	while ((opt = getopt(argc, argv, ":r::")) != -1) {
		switch (opt) {
		case 'r':
			max_depth = optarg ? strtol(optarg, &endptr, 10) : LONG_MAX;

			if (optarg && (max_depth < 0 || *endptr != '\0')) {
				error(EXIT_FAILURE, 0, "Invalid recursion depth -- '%s'"
					USAGE, optarg, program_invocation_short_name);
			}

			break;
		case '?':
			error(EXIT_FAILURE, 0, "Invalid option -- '%c'" USAGE,
				optopt, program_invocation_short_name);
		}
	}

	if (optind >= argc) {
		error(EXIT_FAILURE, 0, "Missing file operand" USAGE,
			program_invocation_short_name);
	}

	if (getrlimit(RLIMIT_NOFILE, &rlimit) == -1) {
		error(EXIT_FAILURE, errno, "getrlimit");
	}

	for (i = optind; i < argc; ++i) {
		ret = nftw(argv[i], printxattr, rlimit.rlim_cur / 2,
			FTW_CHDIR | FTW_PHYS | FTW_ACTIONRETVAL);

		if (ret == -1) {
			error(0, errno, "%s", argv[i]);
		}
	}

	return error_message_count > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
