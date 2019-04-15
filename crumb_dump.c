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

void dumpxattr(int dir_fd, const char *path, int recursive)
{
	int file_fd, ret;
	DIR *nextdir;
	struct dirent *entry;
	struct stat statbuf;
	ssize_t attr_len;
	char attr[PATH_MAX];

	/* NONBLOCK needed to prevent hanging when opening named pipes */
	file_fd = openat(dir_fd, path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);

	if (file_fd == -1) {
		/* For now ignore ELOOP (symbolic links) and ENXIO (sockets)
		   once the daemon supports setting attrs on symlinks, then
		   call open with O_PATH|O_NOFOLLOW to get an fd of a symlink */
		if (errno != ELOOP && errno != ENXIO) {
			perror("openat");
			fprintf(stderr, "(While opening %s)\n", path);
		}

		return;
	}


	attr_len = fgetxattr(file_fd, "user.crumb-exe", attr, sizeof(attr));

	if (attr_len  >= 0) {
		printf("%s%c%.*s%c%c", path, '\0', (int)attr_len, attr, '\0', '\0');
	} else if (errno != ENODATA) {
		perror("fgetxattr");
		fprintf(stderr, "path: %s\n", path);
	}


	if (recursive) {
		ret = fstat(file_fd, &statbuf);

		if (ret == -1) {
			perror("stat");
			fprintf(stderr, "path: %s\n", path);
			goto close_file;
		}

		if (!S_ISDIR(statbuf.st_mode)) {
			goto close_file;
		}

		nextdir = fdopendir(file_fd);

		if (nextdir == NULL) {
			perror("fdopendir");
			goto close_file;
		}

		
		while ((entry = readdir(nextdir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0
			    || strcmp(entry->d_name, "..") == 0) {
				continue;
			}

			dumpxattr(dirfd(nextdir), entry->d_name, recursive);
		}

		closedir(nextdir);
	}

close_file:
	close(file_fd);
}

int main(int argc, char **argv)
{
	int i = 1, recursive = 0;

	if (argc > 1 && strcmp(argv[1], "-r") == 0) {
		recursive = 1;
		++i;
	}

	for (; i < argc; ++i) {
		dumpxattr(AT_FDCWD, argv[i], recursive);
	}

	return EXIT_SUCCESS;
}
