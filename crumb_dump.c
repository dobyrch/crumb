#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

static char **path_list;
static int recursive = 0, max_depth = 64, status = EXIT_SUCCESS;

void dumpxattr(int dir_fd, char *file_name, int path_depth)
{
	int file_fd, ret, i;
	DIR *nextdir;
	struct dirent *entry;
	struct stat statbuf;
	ssize_t attr_len;
	char attr[PATH_MAX];

	/* NONBLOCK needed to prevent hanging when opening named pipes */
	file_fd = openat(dir_fd, file_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);

	if (file_fd == -1) {
		/* For now ignore ELOOP (symbolic links) and ENXIO (sockets)
		   once the daemon supports setting attrs on symlinks, then
		   call open with O_PATH|O_NOFOLLOW to get an fd of a symlink */
		if (errno != ELOOP && errno != ENXIO) {
			fprintf(stderr, "%s: %s\n", file_name, strerror(errno));
			status = EXIT_FAILURE;
		}

		return;
	}


	attr_len = fgetxattr(file_fd, "user.crumb-exe", attr, sizeof(attr));

	if (attr_len  >= 0) {
		for (i = 0; i < path_depth; ++i) {
			printf("%s/", path_list[i]);
		}

		printf("%s%c%.*s%c", file_name, '\0', (int)attr_len, attr, '\0');
	} else if (errno != ENODATA) {
		perror("fgetxattr");
		status = EXIT_FAILURE;
	}


	if (recursive) {
		ret = fstat(file_fd, &statbuf);

		if (ret == -1) {
			perror("stat");
			status = EXIT_FAILURE;
			goto close_file;
		}

		if (!S_ISDIR(statbuf.st_mode)) {
			goto close_file;
		}

		nextdir = fdopendir(file_fd);

		if (nextdir == NULL) {
			perror("fdopendir");
			status = EXIT_FAILURE;
			goto close_file;
		}

		path_list[path_depth++] = file_name;

		if (path_depth >= max_depth) {
			max_depth *= 2;
			path_list = realloc(path_list, max_depth * sizeof(char *));

			if (path_list == NULL) {
				perror("realloc");
				status = EXIT_FAILURE;
				goto close_file;
			}
		}
		
		while ((entry = readdir(nextdir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0
			    || strcmp(entry->d_name, "..") == 0) {
				continue;
			}

			dumpxattr(dirfd(nextdir), entry->d_name, path_depth);
		}

		closedir(nextdir);
	}

close_file:
	close(file_fd);
}

int main(int argc, char **argv)
{
	int i = 1;

	path_list = malloc(max_depth * sizeof(char *));

	if (path_list == NULL) {
		perror("malloc");
		return EXIT_FAILURE;
	}

	if (argc > 1 && strcmp(argv[1], "-r") == 0) {
		recursive = 1;
		++i;
	}

	for (; i < argc; ++i) {
		dumpxattr(AT_FDCWD, argv[i], 0);
	}

	free(path_list);

	return status;
}
