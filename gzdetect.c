#include <zlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>


#define BUFSIZE		4096
#define NAMELEN		30

#define GZ_HDR_LEN	10

#define AD_1990			631170000
#define APPROX_YEAR		31556926


typedef enum {
	// Be picky when finding gzip data. This will reduce false positives,
	// but will reject some valid gzip data that looks weird
	GZ_FIND_STRICT	= 0x1,
} gzdflags;

typedef struct {
	int fd;
	Byte *buf;
	z_stream z;
} rstate;

void parse_args(int argc, char **argv, char **infile, int *idx,
		char **outfile);
int infile_open(char *file, int *fd);
int infile_close(int fd);


// End of a stream's in data
static inline Byte *zsend(rstate *rs) { return rs->z.next_in + rs->z.avail_in; }

// Return zero on success.
int rsread(rstate *rs, Byte *start);

// Find the next location that looks like the start of gzip data. Return
// zero on success.
int gzfind(rstate *rs, gzdflags flags);

// Return zero if this looks like the start of gzip data.
// Assumes the first byte has already been checked, and that GZ_HDR_LEN
// bytes of memory are available at p.
int gzcheck(Byte *p, gzdflags flags);

// Initialize an inflate stream, and get the name
int gzinit(rstate *rs, char *name, size_t namelen);

// Display info about a section of gzip data
int gzlist(size_t idx, rstate *rs);

// Extract a section of gzip data
int gzextract(char *username, rstate *rs);

// Display gzip errors
int gzerr(int err, char *msg, z_stream *s);


int main(int argc, char *argv[]) {
	int idx;
	char *infile, *outfile;
	parse_args(argc, argv, &infile, &idx, &outfile);
	
	int err = 1;
	int fd;
	if (infile_open(infile, &fd))
		goto err;
	
	// Find gzip bits
	Byte buf[BUFSIZE];
	rstate rs = { .fd = fd, .buf = buf, .z = {
		.opaque = Z_NULL, .zalloc = Z_NULL, .zfree = Z_NULL,
		.next_in = buf, .avail_in = 0
	} };
	
	size_t found = 0;
	while (gzfind(&rs, GZ_FIND_STRICT) == 0) {
		++found;
		if (idx == found) {
			if (gzextract(outfile, &rs))
				goto err;
			break;
		} else if (idx) {	// Don't repeat this find
			++rs.z.next_in;	// Always safe, since we checked header
			--rs.z.avail_in;
		} else {
			if (gzlist(found, &rs))
				goto err;
		}
	}
	
	if (found == 0) {
		fprintf(stderr, "No gzip data found.\n");
		goto err;
	}
	if (idx > found) {
		fprintf(stderr, "Less than %d sections of gzip data.\n", idx);
		goto err;
	}
	
	err = 0;
	
err:
	if (rs.z.zalloc) {
		if (gzerr(inflateEnd(&rs.z), "Error ending inflation", &rs.z))
			err = 1;
	} 
	err |= infile_close(fd);
	return err;
}


void parse_args(int argc, char **argv, char **infile, int *idx,
		char **outfile) {
	if (argc < 2 || argc > 4)
		goto usage;
	
	*infile = argv[1];
	*idx = 0;
	*outfile = NULL;
	if (argc >= 3) {
		char *endp;
		*idx = strtol(argv[2], &endp, 10);
		if (*argv[2] == '\0' || *endp != '\0' || *idx < 1)
			goto usage;
		
		if (argc >= 4)
			*outfile = argv[3];
	}
	return;
	
usage:
	fprintf(stderr, "Usage: gzdetect FILE [IDX [OUT]]\n");
	exit(-1);
}
	
int infile_open(char *file, int *fd) {
	if ((*fd = open(file, O_RDONLY)) == -1) {
		perror("Can't open input file");
		return 1;
	}
	return 0;
}

int infile_close(int fd) {
	if (close(fd) == -1) {
		perror("Can't close input file");
		return 1;
	}
	return 0;
}

int rsread(rstate *rs, Byte *start) {
	size_t keep = 0;
	if (start) {
		keep = zsend(rs) - start;
		if (keep)
			memmove(rs->buf, rs->z.next_in, keep);
	}
	
	int ret = read(rs->fd, rs->buf + keep, BUFSIZE - keep);
	if (ret == -1) {
		perror("Read error");
		return 1;
	}
	
	rs->z.next_in = rs->buf;
	rs->z.avail_in = keep + ret;
	return 0;
}

int gzfind(rstate *rs, gzdflags flags) {
	Byte *p = rs->z.next_in;
	while (1) {
		if (p >= zsend(rs)) {
			if (rsread(rs, NULL))
				return 1;
			p = rs->z.next_in;
			if (p >= zsend(rs)) // ran out of input
				return 1;
		}
		
		p = memchr(p, 0x1f, zsend(rs) - p);
		if (p == NULL) {
			p = zsend(rs);
			continue;
		}
		
		// We have a match!
		if (p + GZ_HDR_LEN > zsend(rs)) { // We want a complete header
			if (rsread(rs, p))
				return 1;
			p = rs->z.next_in;
			if (p + GZ_HDR_LEN > zsend(rs)) // Couldn't read enough for header!
				return 1;
		}
		
		if (gzcheck(p, flags) == 0) {
			rs->z.avail_in -= p - rs->z.next_in;
			rs->z.next_in = p;
			return 0;
		} else {
			++p;
		}
	}
}

int gzcheck(Byte *p, gzdflags flags) {
	if (p[1] != 0x8b || p[2] != 0x08)
		return 1;
	
	if ((p[3] & 0xe0) != 0) // ... reserved bits of flag ...
		return 1;
	
	// Make sure time is zero or a reasonable value
	// (gzip was invented around 1992).
	if (flags & GZ_FIND_STRICT) {
		time_t mtime = (time_t)p[4] + ((time_t)p[5] << 8)
			+ ((time_t)p[6] << 16) + ((time_t)p[7] << 24);
		if (mtime != 0 && (mtime < AD_1990 || mtime > time(NULL) + APPROX_YEAR))
			return 1;
	}
	
	// ... extra flags ...
	Byte xfl = p[8];
	if (xfl != 2 && xfl != 4 && xfl != 0)
		return 1;
	
	// known values for OS
	if (flags & GZ_FIND_STRICT) {
		if (p[9] > 13 && p[9] != 255)
			return 1;
	}
	
	return 0;
}

int gzerr(int err, char *msg, z_stream *s) {
	if (err) {
		fprintf(stderr, "%s: %s%s%s\n", msg,
			(err == Z_ERRNO) ? strerror(errno) : zError(err),
			s->msg ? " - " : "",
			s->msg ? s->msg : "");
	}
	return err;
}

int gzinit(rstate *rs, char *name, size_t namelen) {
	gz_header hdr = { .extra = Z_NULL, .comment = Z_NULL, .name = (Byte*)name,
		.name_max = namelen };
	rs->z.avail_out = 0;
	Byte dummy;
	rs->z.next_out = &dummy; 	// If avail_out is zero, why do we need this?
								// Silly zlib!
	
	if (rs->z.zfree == NULL) {
		if (gzerr(inflateInit2(&rs->z, 15 + 16 /* gzip only */),
				"INFLATE initialization failed", &rs->z))
			return 1;
	} else {
		if (gzerr(inflateReset(&rs->z), "INFLATE reset failed", &rs->z))
			return 1;
	}
	
	*name = '\0';
	if (gzerr(inflateGetHeader(&rs->z, &hdr), "Getting gzip headers failed",
			&rs->z))
		return 1;
	
	while (!hdr.done) {
		int zerr = inflate(&rs->z, Z_BLOCK);
		if (zerr == Z_BUF_ERROR) {
			if (rsread(rs, rs->z.next_in))
				return 1;
		} else if (zerr) {
			gzerr(zerr, "Inflating gzip headers failed", &rs->z);
			return 1;
		}
	}
	
	name[namelen - 1] = '\0';
	return 0;
}

int gzlist(size_t idx, rstate *rs) {
	off_t off;
	if ((off = lseek(rs->fd, 0, SEEK_CUR)) == -1)
		return 1;
	off -= rs->z.avail_in;
	
	char name[NAMELEN];
	if (gzinit(rs, name, NAMELEN))
		return 1;
	fprintf(stderr, "%2zu: %#010llx  %s\n", idx, (unsigned long long)off, name);
	return 0;
}

int gzextract(char *username, rstate *rs) {
	char gzname[NAMELEN];
	if (gzinit(rs, gzname, NAMELEN))
		return 1;
	
	// Get output file settings
	int oflags = O_WRONLY | O_CREAT | O_TRUNC;
	char *name = username;
	if (!name) {
		oflags |= O_EXCL; // don't replace if the user didn't ask for it
		if (*gzname && strchr(gzname, '/') == 0)
			name = gzname; // looks trustable
		else
			name = "gzdetect.out";
	}
	
	// Open output file
	int ofd = open(name, oflags, 0666);
	if (ofd == -1) {
		if (errno == EEXIST)
			fprintf(stderr, "Generated filename '%s' already exists,"
				" not replacing.\n", name);
		else
			perror("Can't open output file");
		return 1;
	}
	Byte obuf[BUFSIZE];
	int err = 1;
	
	int zerr;
	while (1) {
		// inflate until didn't fill output
		do {
			rs->z.avail_out = BUFSIZE;
			rs->z.next_out = obuf;
			zerr = inflate(&rs->z, Z_NO_FLUSH);
			if (zerr != Z_OK && zerr != Z_BUF_ERROR && zerr != Z_STREAM_END) {
				gzerr(zerr, "Error during inflation", &rs->z);
				goto cleanup;
			}
			size_t have = BUFSIZE - rs->z.avail_out;
			if (write(ofd, obuf, have) != have) {
				perror("Error writing output");
				goto cleanup;
			}
		} while (rs->z.avail_out == 0);
		
		if (zerr == Z_STREAM_END)
			break; // we're done!
		
		// gotta read more
		if (rsread(rs, rs->z.next_in))
			goto cleanup;
		if (rs->z.avail_in == 0) {
			fprintf(stderr, "Inflate ran out of input!\n");
			goto cleanup;
		}
	}
 	err = 0;
	
cleanup:
	if (close(ofd) == -1) {
		perror("Error closing output");
		err = 1;
	}
	return err;
}
