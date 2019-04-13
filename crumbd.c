#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fanotify.h>
#include <sys/xattr.h>

/* TODO: Delete these definitions once they're provided by the headers */
/* =================================================================== */
#define FAN_CREATE              0x00000100
#define FAN_MARK_FILESYSTEM     0x00000100
#define FAN_REPORT_FID          0x00000200
#define FAN_REPORT_FILENAME     0x00000400

#define FAN_EVENT_INFO_TYPE_FID 1

struct fanotify_event_info_header {
	__u8 info_type;
	__u8 pad;
	__u16 len;
};

struct fanotify_event_info_fid {
	struct fanotify_event_info_header hdr;
	__kernel_fsid_t fsid;
	unsigned char handle[0];
};
/* =================================================================== */

#define BUF_SIZE 4096

void process_fanotify_event(int event_fd)
{
	int ret, dir_fd, file_fd;
	ssize_t event_len, exe_len, dir_len;

	char events_buf[BUF_SIZE];
	char proc_path[PATH_MAX];
	char exe_path[PATH_MAX];
	char dir_path[PATH_MAX];
	char *file_name;

	struct fanotify_event_metadata *metadata;
	struct fanotify_event_info_fid *fid;
	struct file_handle *file_handle;


	event_len = read(event_fd, (void *) &events_buf, sizeof(events_buf));

	if (event_len == -1) {
		perror("read");
		return;
	}

	for (metadata = (struct fanotify_event_metadata *) events_buf;
			FAN_EVENT_OK(metadata, event_len);
			metadata = FAN_EVENT_NEXT(metadata, event_len)) {

		snprintf(proc_path, sizeof(proc_path),
			"/proc/%d/exe", metadata->pid);
		exe_len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);

		if (exe_len == -1) {
			/* If readlink fails (most likely because the process
			   that created the new file has already exited), then
			   just use an empty string as the exe path */
			exe_len = 0;

			if (errno != ENOENT) {
				perror("readlink (exe)");
			}
		}

		exe_path[exe_len] = '\0';


		fid = (struct fanotify_event_info_fid *) (metadata + 1);

		if (fid->hdr.info_type != FAN_EVENT_INFO_TYPE_FID) {
			fprintf(stderr, "Received unexpected event type\n");
			continue;
		}

		file_handle = (struct file_handle *) fid->handle;
		dir_fd = open_by_handle_at(AT_FDCWD, file_handle, O_RDONLY);

		if (dir_fd == -1) {
			perror("open_by_handle_at");
			continue;
		}

		snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dir_fd);
		dir_len = readlink(proc_path, dir_path, sizeof(dir_path) - 1);

		if (dir_len == -1) {
			perror("readlink (dir)");
			goto close_dir;
		}

		dir_path[dir_len] = '\0';


		/* TODO: What are these extra eight bytes? */
		file_name = (char *) (file_handle + 1);
		file_name += 8;
		file_fd = openat(dir_fd, file_name, O_RDONLY);

		if (file_fd == -1) {
			/* Temporary files tend to pop in and out of existence;
			   no need to log an error if the file is already gone */
			if (errno != ENOENT) {
				perror("openat");
			}

			goto close_dir;
		}

		printf("Creator: %s (pid %d)\n", exe_path, metadata->pid);
		printf("Created: %s/%s\n\n", dir_path, file_name);

		ret = fsetxattr(file_fd, "user.crumb-exe", exe_path, exe_len, 0);

		if (ret == -1 ) {
			perror("fsetxattr");
			goto close_file;
		}

close_file:
		close(file_fd);
close_dir:
		close(dir_fd);
	}
}

int main(int argc, char **argv)
{
	int fd, ret;

	fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_FILENAME, 0);
	if (fd == -1) {
		perror("fanotify_init");
		exit(EXIT_FAILURE);
	}

	ret = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
		FAN_CREATE | FAN_ONDIR,
		AT_FDCWD, "/home");
	if (ret == -1) {
		perror("fanotify_mark");
		exit(EXIT_FAILURE);
	}

	for (;;) {
		process_fanotify_event(fd);
	}
}
