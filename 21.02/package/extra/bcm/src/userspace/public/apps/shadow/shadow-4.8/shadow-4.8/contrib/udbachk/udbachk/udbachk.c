/* This is a passwd, group, shadow and gshadow file integrity checker.
 * Copyright (C) 1999 Sami Kerola and Janne Riihijärvi
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * You can contact the authors using the following email addresses:
 *
 * Sami Kerola <kerolasa@iki.fi>
 * Janne Riihijärvi <jariihij@mail.student.oulu.fi> */

/************
 * Includes *
 ************/
#include <dirent.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

/***************
 * Definitions *
 ***************/
/* Builtin default paths.
 * If you wish to drop some files out of defaults just don't define the path */
#define PATH_TO_PASSWD	"/etc/passwd"
#define PATH_TO_GROUP	"/etc/group"
#define PATH_TO_SHADOW	"/etc/shadow"
#define PATH_TO_GSHADOW "/etc/gshadow"

/* What mode files should be.
 * Note: value is not umask, it's the one you use with chmod command  */
#define MODE_FOR_PASSWD  644
#define MODE_FOR_GROUP	 644
#define MODE_FOR_SHADOW  400
#define MODE_FOR_GSHADOW 400

/* Maximum line length is used in buffering and should be set big enough */
#define MAX_LINE_LEN	1024

/* Maximun lenght of a path in configuration file */
#define MAX_PATH_LEN	 256

/* Location of the global configuration file */
#define CONFIGURATION_FILE "/usr/local/etc/udbachk.conf"

/***********************
 * Function prototypes *
 ***********************/
int field_n_to_int(char *line, int n);
int getgrpmember(int g_or_s, char *grp_line, FILE *group_file, int col);
int intcomp(const void *x, const void *y);
void chkgroup(FILE *group_file, char *logins, int *passwd_gids, int g_or_s);
void chkoneself(void);
void chkpasswdline(char *line, int lno);
void chkshadow(FILE *shadow_file, char *logins);
int chkshadowline(char *line, int lno);
int configfile(void);
FILE *openfile(char *path, int perm_mode);
int stringcomp(const void *s1, const void *s2);
void usage(void);
void version(void);
void worker(FILE *pw_file, FILE *grp_file, FILE *shadow, FILE *shadowgrp);

/********************
 * Global variables *
 ********************/
char *programname;
const float version_number = 0.11;
FILE *my_stdout;

/* Configuration struct */
struct configuration {
    char passwd_path[MAX_PATH_LEN];
    char group_path[MAX_PATH_LEN];
    char shadow_path[MAX_PATH_LEN];
    char gshadow_path[MAX_PATH_LEN];
    int passwd_mode;
    int group_mode;
    int shadow_mode;
    int gshadow_mode;
    int loginlength;
    int grouplenght;
    long minuid;
    long maxuid;
    long mingid;
    long maxgid;
};

/* Variable containing the configuration information */
struct configuration config;

/* Counters for how many lines there are in the passwd file
 * and how many characters long is the longest login there */
int passwd_lines = 0, longest_login = 0, previous_line = 0;

/* getopt_long() uses this struct to parse arguments */
static struct option const long_options[] =
{
    {"default", no_argument, 0, 'd'},
    {"passwd", no_argument, 0, 'p'},
    {"group", no_argument, 0, 'g'},
    {"shadow", no_argument, 0, 's'},
    {"gshadow", no_argument, 0, 'G'},
    {"file", no_argument, 0, 'f'},
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

/******************
 * Program itself *
 ******************/

/* A simple (predicate-like) integer comparison function (for qsort) */
int intcomp(const void *x, const void *y)
{
    if (*(int *) x < *(int *) y)
	return (-1);
    else if (*(int *) y < *(int *) x)
	return (1);
    else
	return (0);
}

/* A simple (predicate-like) string comparison function (for qsort) */
int stringcomp(const void *s1, const void *s2)
{
    return (strcmp((const char *) s1, (const char *) s2));
}

/* Read the n'th field and return it typecasted to int */
int field_n_to_int(char *line, int n)
{
    int field = 0, i = 0;

    while (i < MAX_LINE_LEN + 1) {
	if (line[i] == ':')
	    field++;
	if (field == n - 1) {
	    field = atoi(&line[i + 1]);
	    return (field);
	}
	i++;
    }
    return (-1);
}

/* Function for solving group members one by one */
int getgrpmember(int g_or_s, char *grp_line, FILE *group_file, int col)
{
    int i = 0, ch = 0;
    while (!feof(group_file)) {
	ch = fgetc(group_file);

	/* When a colon is encountered */
	if (ch == ':')
	    col++;

	/* Next line */
	if (ch == '\n') {
	    grp_line[i] = '\0';
	    return (0);
	}
	/* Next member, delimeter is , */
	if (ch == ',' || ch == ':') {
	    grp_line[i] = '\0';
	    return (col);
	}
	/* Take the member but don't take passwd or group name */
	if (((g_or_s == 0 && col == 2) || col == 3) && ch != ':' && ch != ',' && ch != '\n') {
	    if ((ch == ' ' || ch == '\t') && i == 0);
	    else {
		grp_line[i] = ch;
		i++;
	    }
	}
	/* When file ends */
	if (feof(group_file)) {
	    grp_line[i] = '\0';
	    return (0);
	}
    }

    /* Failure */
    return (-1);
}

/* Configuration file parser */
int configfile(void)
{
    FILE *config_file;
    char line[MAX_PATH_LEN], confname[MAX_PATH_LEN], confdata[MAX_PATH_LEN],
     tmpstr[MAX_PATH_LEN], *comment;
    int i, lno;
    long tmp;

    /* Set config struct defaults */
    config.passwd_mode = 644;
    config.group_mode = 644;
    config.shadow_mode = 400;
    config.gshadow_mode = 400;
    config.loginlength = 8;
    config.grouplenght = 24; /* A wild guess... */
    config.minuid = 0;
    config.maxuid = 65534;
    config.mingid = 0;
    config.maxgid = 65534;

    /* Create path to a config file in the home directory */
    comment = getenv("HOME");
    strncpy(tmpstr, comment, MAX_PATH_LEN);
    strncat(tmpstr, "/.udbachk.conf", MAX_PATH_LEN - (strlen(tmpstr)));

    /* Open the config file from home */
    config_file = fopen(tmpstr, "r");
    if (config_file == NULL)
	/* If configuration file was not in home dir try the global file */
	config_file = fopen(CONFIGURATION_FILE, "r");
    if (config_file == NULL)
	/* No file... leave the function */
	return (1);

    /* Read all the lines, clean the comments and do the stuff */
    for (lno = 0; !feof(config_file); lno++) {
	fgets(line, MAX_PATH_LEN, config_file);
	/* Find a comment character and cut the line there */
	comment = (char *) strchr(line, '#');
	if (comment) {
	    /* In case of loooong line */
	    if (strlen(line) > MAX_PATH_LEN - 1)
		fscanf(config_file, "%*[^\n]");
	    *comment = '\0';
	    *(++comment) = '\0';
	}
	/* Some of us use = and " characters, strip them out */
	for (i = 0; i < strlen(line); i++) {
	    if (line[i] == '=' || line[i] == '"')
		line[i] = '\t';
	}

	confdata[0] = '\0';

	/* Clean the configuration data */
	if (strlen(line) > 1) {
	    /* tmpstr removes white spaces from begining */
	    sscanf(line, "%s%[\t ]%[^\n]s", confname, tmpstr, confdata);
	    /* this for cleans white spaces from end of line */
	    for (i = (strlen(confdata) - 1); i > 0; i--) {
		if (confdata[i] == ' ' || confdata[i] == '\t') {
		    confdata[i] = '\0';
		} else {
		    i = 1;
		}
	    }

	    /* Put the configuration data into the configuration struct */
	    if (!strcmp("PATH_TO_PASSWD", confname))
		strncpy(config.passwd_path, confdata, MAX_PATH_LEN);
	    else if (!strcmp("PATH_TO_GROUP", confname))
		strncpy(config.group_path, confdata, MAX_PATH_LEN);
	    else if (!strcmp("PATH_TO_SHADOW", confname))
		strncpy(config.shadow_path, confdata, MAX_PATH_LEN);
	    else if (!strcmp("PATH_TO_GSHADOW", confname))
		strncpy(config.gshadow_path, confdata, MAX_PATH_LEN);
	    else if (!strcmp("MODE_FOR_PASSWD", confname)) {
		tmp = atoi(confdata);
		if (tmp > -1 && tmp < 1000)
		    config.passwd_mode = tmp;
	    } else if (!strcmp("MODE_FOR_GROUP", confname)) {
		tmp = atoi(confdata);
		if (tmp > -1 && tmp < 1000)
		    config.group_mode = tmp;
	    } else if (!strcmp("MODE_FOR_SHADOW", confname)) {
		tmp = atoi(confdata);
		if (tmp > -1 && tmp < 1000)
		    config.shadow_mode = tmp;
	    } else if (!strcmp("MODE_FOR_GSHADOW", confname)) {
		tmp = atoi(confdata);
		if (tmp > -1 && tmp < 1000)
		    config.gshadow_mode = tmp;
	    } else if (!strcmp("LONGEST_LOGIN_NAME", confname))
		config.loginlength = atoi(confdata);
	    else if (!strcmp("LONGEST_GROUP_NAME", confname))
		config.grouplenght = atoi(confdata);
	    else if (!strcmp("MIN_UID", confname))
		config.minuid = atol(confdata);
	    else if (!strcmp("MAX_UID", confname))
		config.maxuid = atol(confdata);
	    else if (!strcmp("MIN_GID", confname))
		config.mingid = atol(confdata);
	    else if (!strcmp("MAX_GID", confname))
		config.maxgid = atol(confdata);
	    else
		/* case default. Hmm switch-case might have been a good idea.
		 * Well, too late for it now */
		fprintf(my_stdout, "In line %d: unidentified configuration \"%s\"\n", lno + 1, confname);
	    confdata[0] = '\0';
	}
    }
    /* Go away and don't come back */
    return (0);
}

/* Open a file and check permissions */
FILE *openfile(char *path, int perm_mode)
{
    int stat_error, real_perm = 0, owner, groupmembers, others;
    struct stat S;

    /* Read what kind of wile we are dealing */
    stat_error = lstat(path, &S);
    if (stat_error)
	/* Failure */
	return (NULL);
    owner = S.st_mode;
    stat(path, &S);

    /* What we learned about file we're dealing */
    if (S_ISREG(owner));
    else if (S_ISLNK(owner))
	fprintf(my_stdout, "File \"%s\" is a symbolic link\n", path);
    else {
	fprintf(my_stdout, "Alert! %s is not a file or symbolic link and it will not be opened\n", path);
	/* Failure */
	return (NULL);
    }

    /* Root ought to own the files */
    if (S.st_uid)
	fprintf(my_stdout, "UID 0 does not own file \"%s\"\n", path);
    if (S.st_gid)
	fprintf(my_stdout, "GID 0 does not own file \"%s\"\n", path);

    /* Get real file permissions and compare them with the wanted permissions */
    owner = perm_mode / 100;
    groupmembers = (perm_mode - owner * 100) / 10;
    others = perm_mode - (groupmembers * 10) - (owner * 100);

    /* Owner */
    if (owner < 8) {
	if (S.st_mode & S_IRUSR)
	    real_perm += 400;
	if (S.st_mode & S_IWUSR)
	    real_perm += 200;
	if (S.st_mode & S_IXUSR)
	    real_perm += 100;
    } else
	owner -= owner;

    /* Group */
    if (groupmembers < 8) {
	if (S.st_mode & S_IRGRP)
	    real_perm += 40;
	if (S.st_mode & S_IWGRP)
	    real_perm += 20;
	if (S.st_mode & S_IXGRP)
	    real_perm += 10;
    } else
	groupmembers -= groupmembers;

    /* Others */
    if (others < 8) {
	if (S.st_mode & S_IROTH)
	    real_perm += 4;
	if (S.st_mode & S_IWOTH)
	    real_perm += 2;
	if (S.st_mode & S_IXOTH)
	    real_perm += 1;
    } else
	others -= others;

    perm_mode = (owner * 100) + (groupmembers * 10) + others;

    /* Test whether permissions are what you wanted */
    if (real_perm != perm_mode)
	fprintf(my_stdout, "Permissions of file \"%s\" are %.3d but they should be %.3d\n", path, real_perm, perm_mode);

    /* Other file checks (I came up with only one sensible) */
    if (S.st_nlink != 1)
	fprintf(my_stdout, "File \"%s\" has %d hard link%sto it\n", path, S.st_nlink - 1, S.st_nlink > 2 ? "s " : " ");

    /* Finally open the file */
    return (fopen(path, "r"));
}

/* Password file line checker */
void chkpasswdline(char *line, int lno)
{
    int i, j = 0, col = 0, owner, group;
    char path[MAX_LINE_LEN];
    struct stat homeshell;

    /* Complain, if the last line had a wrong number of colons.
     * This check is done now to avoid an unnecessery error report
     * if the final line of the passwd file happens to be empty. */
    if (previous_line) {
	fprintf(my_stdout, "Alert! In line %d there is wrong number \"%d\" of colons\n", lno - 1, previous_line);
	previous_line = 0;
    }

    /* Get uid and gid of the line, these are needed later */
    owner = field_n_to_int(line, 3);
    group = field_n_to_int(line, 4);

    for (i = 0; i < strlen(line); i++, j++) {

	/* Some character-specific sanity checks */

	/* login */
	if (col == 0 && line[i] != ':')
	    if (line[i] > 96 && line[i] < 123);
	    else if (line[i] > 47 && line[i] < 58);
	    else if (line[i] > 64 && line[i] < 91)
		fprintf(my_stdout, "In line %d login has an uppercase character \"%c\" \n", lno, line[i]);
	    else
		fprintf(my_stdout, "Alert! In line %d login has an illegal character \"%c\"\n", lno, line[i]);

	/* encrypted password */
	if (col == 1 && line[i] != ':')
	    if (line[i] > 96 && line[i] < 123);
	    else if (line[i] > 45 && line[i] < 58);
	    else if (line[i] > 64 && line[i] < 91);
	    else
		fprintf(my_stdout, "Invalid encrypted password in line %d. Possibly a locked account. \"%c\"\n", lno, line[i]);

	/* UID */
	if (col == 2 && line[i] != ':')
	    if (line[i] < 48 || line[i] > 57)
		fprintf(my_stdout, "Alert! UID in line %d has an illegal character \"%c\"\n", lno, line[i]);

	/* GID */
	if (col == 3 && line[i] != ':')
	    if (line[i] < 48 || line[i] > 57)
		fprintf(my_stdout, "Alert! GID in line %d has an illegal character \"%c\"\n", lno, line[i]);

	/* home directory */
	if (col == 5) {
	    path[j - 1] = line[i];
	    if (line[i] == ':')
		path[j - 1] = '\0';
	}
	/* login shell */
	if (col == 6) {
	    path[j - 1] = line[i];
	    if (line[i] == '\n' || line[i] == ' ' || line[i] == '\t')
		path[j - 1] = '\0';
	    if (line[i + 1] == '\0') {
		path[j] = '\0';
	    }
	}
	/* When a colon ":" is encountered some checks are done */
	if (line[i] == ':') {
	    if (j > config.loginlength && col == 0)
		fprintf(my_stdout, "In line %d there is a %d characters long login name\n", lno, j);
	    else if (j == 0 && col == 0)
		fprintf(my_stdout, "Alert! Zero length login name in line %d\n", lno);
	    else if (j == 1 && col == 1)
		fprintf(my_stdout, "Line %d has an empty password field\n", lno);
	    else if (j == 1 && col == 4)
		fprintf(my_stdout, "Weird: line %d has nothing in GEGOS field\n", lno);
	    else if (col == 5) {
		int statreturn;
		statreturn = stat(path, &homeshell);
		if (statreturn)
		    fprintf(my_stdout, "Alert! In line %d home directory \"%s\" does not exist\n", lno, path);
		else if (path[0] != '/')
		    fprintf(my_stdout, "Alert! In line %d home directory \"%s\" is not an absolute path\n", lno, path);
		else if (S_ISDIR(homeshell.st_mode)) {
		    if (homeshell.st_uid != owner)
			fprintf(my_stdout, "In line %d user does not own the home directory\n", lno);
		    if (homeshell.st_gid != group)
			fprintf(my_stdout, "In line %d user isn't primary member in the group owning the home directory\n", lno);
		} else
		    fprintf(my_stdout, "In line %d home directory is not a directory\n", lno);
	    }
	    if (j > longest_login && col == 0)
		longest_login = j;
	    col++;
	    j = 0;
	}
    }

    /* password line does not end in a colon so here's the last check */
    if (col == 6) {
	j = stat(path, &homeshell);
	if (j)
	    fprintf(my_stdout, "Alert! In line %d shell \"%s\" does not exist\n", lno, path);
	else if (S_ISREG(homeshell.st_mode)) {
	    if (S_IXOTH & homeshell.st_mode || owner == 0);
	    else if ((S_IXGRP & homeshell.st_mode) && homeshell.st_gid == group);
	    else if ((S_IXUSR & homeshell.st_mode) && homeshell.st_uid == owner);
	    else
		fprintf(my_stdout, "Shell in line %d is not executable to the user\n", lno);
	} else
	    fprintf(my_stdout, "In line %d shell is not a regular file\n", lno);
    }
    /* c.f. the first commentary for this subroutine */
    if (col != 6)
	previous_line = col;
}

/* Check that program is executed by root */
/* Note: This is a beta version and suid is not approved because
 * uncertainity of program stability. I'm wondering if this program is
 * suitable at all for an end user command */
void chkoneself(void)
{
    uid_t realuid = getuid();
    uid_t euid = geteuid();

    if (realuid != 0 && euid == 0)
	/* Please read note 9 lines above this */
	fprintf(stderr, "This is a beta release and might cause a security risk when run suid\n");
    if (realuid != 0) {
	fprintf(stderr, "Please login as root and retry\n");
	exit(1);
    }
}

/* Check a line of the shadow file */
int chkshadowline(char *line, int lno)
{
    int col = 0, collen = 0, i, shadowloginlen = 0, wrongchar = 0;

    /* Complain, if the last line had a wrong number of colons.
     * This check is done now to avoid an unnecessery error report
     * if the final line of the shadow file happens to be empty. */
    if (previous_line) {
	fprintf(my_stdout, "Alert! Wrong number \"%d\" of colons in line %d\n", previous_line, lno - 1);
	previous_line = 0;
    }
    for (i = 0; i < strlen(line); i++, collen++) {

	/* Shadow login length */
	if (col == 0 && line[i] == ':')
	    shadowloginlen = collen;

	/* Encrypted passwd */
	if (col == 1 && line[i] != ':') {
	    if (line[i] > 96 && line[i] < 123);
	    else if (line[i] > 45 && line[i] < 58);
	    else if (line[i] > 64 && line[i] < 91);
	    else
		wrongchar = 1;
	}
	/* Check password */
	if (col == 1 && line[i] == ':') {
	    if ((collen != 14 && collen != 0) || wrongchar)
		fprintf(my_stdout, "Locked account in line %d\n", lno);
	    wrongchar = 0;
	    if (collen == 1)
		fprintf(my_stdout, "Line %d has no password\n", lno);
	}
	/* Reserved field */
	if (col == 8 && collen > 1 && line[i + 1] == '\0')
	    fprintf(my_stdout, "Reserved field contains trash in line %d\n", lno);

	if (line[i] == ':') {
	    collen = 0;
	    col++;
	}
    }

    /* Colons, disabled logins and disabling warnings */
    if (col != 8)
	/* c.f. the first commentary for this subroutine */
	previous_line = col;
    else {
	time_t currentday;
	time(&currentday);
	/* Days since Jan 1, 1970 */
	currentday = currentday / (24 * 60 * 60);

	i = field_n_to_int(line, 8);
	if (i > 0) {
	    if (i <= currentday)
		fprintf(my_stdout, "Account in line %d is disabled\n", lno);
	    i = field_n_to_int(line, 7);
	    if (i < 1)
		fprintf(my_stdout, "Account in line %d can be disabled without a user warning\n", lno);
	}
	i = field_n_to_int(line, 3);
	if (i > currentday)
	    fprintf(my_stdout, "In line %d user invented time machine and chanced password %d days from now\n", lno, i - (int) currentday);
    }
    return (shadowloginlen);
}

/* main... all begins from here if you don't know it already */
int main(int argc, char **argv)
{
    FILE *pw_file = '\0', *grp_file = '\0', *shadow = '\0', *shadowgrp = '\0';
    int c;

    programname = argv[0];
    /* If you would like to print into a file by default open my_stdout
     * as a writable file and that is all what needs to be done */
    my_stdout = stdout;

    /* Permission to run this program */
    chkoneself();

    /* Set defaults and read the configuration file */
    configfile();

    /* Parse options */
    while (1) {
	c = getopt_long(argc, argv, "dpgsGfqvh", long_options, (int *) 0);

	if (c == EOF)
	    break;

	switch (c) {
	    case 0:
		break;
	    case 'd':
		strncpy(config.passwd_path, PATH_TO_PASSWD, MAX_PATH_LEN);
		strncpy(config.group_path, PATH_TO_GROUP, MAX_PATH_LEN);
		strncpy(config.shadow_path, PATH_TO_SHADOW, MAX_PATH_LEN);
		strncpy(config.gshadow_path, PATH_TO_GSHADOW, MAX_PATH_LEN);
		break;
	    case 'p':
		if (argv[optind] != NULL)
		    strncpy(config.passwd_path, argv[optind], MAX_PATH_LEN);
		break;
	    case 'g':
		if (argv[optind] != NULL)
		    strncpy(config.group_path, argv[optind], MAX_PATH_LEN);
		break;
	    case 's':
		if (argv[optind] != NULL)
		    strncpy(config.shadow_path, argv[optind], MAX_PATH_LEN);
		break;
	    case 'G':
		if (argv[optind] != NULL)
		    strncpy(config.gshadow_path, argv[optind], MAX_PATH_LEN);
		break;
	    case 'f':
		fclose(my_stdout);
		my_stdout = fopen(argv[optind], "w");
		if (my_stdout == NULL) {
		    fprintf(stderr, "I could not open output file \"%s\" opening /dev/stdout\n", argv[optind]);
		    my_stdout = stdout;
		}
		break;
	    case 'v':
		version();
		exit(0);
	    case 'h':
		usage();
		exit(0);
	    default:
		usage();
		exit(1);
	}
    }

    /* Open files which we're going to examine and if files won't open up
     * tell it to user */
    if (config.passwd_path)
	pw_file = openfile(config.passwd_path, config.passwd_mode);
    if (strlen(config.group_path)) {
	grp_file = openfile(config.group_path, config.group_mode);
	if (grp_file == NULL)
	    fprintf(my_stdout, "group file \"%s\" could not be opened\n", config.group_path);
    }
    if (strlen(config.shadow_path)) {
	shadow = openfile(config.shadow_path, config.shadow_mode);
	if (shadow == NULL)
	    fprintf(my_stdout, "shadow file \"%s\" could not be opened\n", config.shadow_path);
    }
    if (strlen(config.gshadow_path)) {
	shadowgrp = openfile(config.gshadow_path, config.gshadow_mode);
	if (shadowgrp == NULL)
	    fprintf(my_stdout, "gshadow file \"%s\" could not be opened\n", config.gshadow_path);
    }
    /* Do the job and check that passwd is open which is The Most Important
     * File */
    if (pw_file != NULL)
	worker(pw_file, grp_file, shadow, shadowgrp);
    else {
	fprintf(my_stdout, "Please check manually why passwd file could not be opened\n");
	usage();
    }

    /* Clean up and return  */
    if (pw_file != NULL)
	fclose(pw_file);
    if (grp_file != NULL)
	fclose(grp_file);
    if (shadowgrp != NULL)
	fclose(shadowgrp);
    if (shadow != NULL)
	fclose(shadow);
    fclose(my_stdout);

    return (0);
    /* Program ends here if everything went fine */
}

/* Work begins and passwd will be checked first */
void worker(FILE *pw_file, FILE *grp_file, FILE *shadow_file, FILE *shadowgrp)
{
    int i = 0, same = 0, *uid, *gid;
    char pw_line[MAX_LINE_LEN + 1], *login;

    /* Passwd file */

    fprintf(my_stdout, "\
*****************\n\
* Password file *\n\
*****************\n");

    /* Find out the number of lines in the passwd file */
    while (!feof(pw_file)) {
	fgets(pw_line, MAX_LINE_LEN, pw_file);
	/* Go to line checking subroutine */
	chkpasswdline(pw_line, (passwd_lines + 1));
	if (strlen(pw_line) != 0 && feof(pw_file))
	    fprintf(my_stdout, "passwd file does not end in a linefeed\n");
	passwd_lines++;
	pw_line[0] = '\0';
    }

    /* Last passwd line should be empty (looks like -> ...\n\nEOF) */
    if (strlen(pw_line) != 0)
	fprintf(my_stdout, "passwd file does not end in a linefeed\n");

    /* Add space for null */
    longest_login++;

    /* Allocate some space for the uids, gids and logins */
    uid = (int *) malloc((passwd_lines + 1) * sizeof(int));
    gid = (int *) malloc((passwd_lines + 1) * sizeof(int));
    login = (char *) malloc((longest_login + 1) * passwd_lines * sizeof(char));

    if (uid == NULL || gid == NULL || login == NULL) {
	printf("Memory allocation failure\n");
	exit(1);
    }
    rewind(pw_file);
    i = 0;

    /* Read the uids, gids and logins */
    while (!feof(pw_file)) {
	fgets(pw_line, MAX_LINE_LEN, pw_file);
	uid[i] = field_n_to_int(pw_line, 3);
	gid[i] = field_n_to_int(pw_line, 4);
	sscanf(pw_line, "%[^:]s", &login[i * longest_login]);
	i++;
    }

    /* Sort the uids, gids and logins */
    qsort(uid, passwd_lines - 1, sizeof(int), &intcomp);
    qsort(gid, passwd_lines - 1, sizeof(int), &intcomp);
    qsort(login, passwd_lines - 1, (sizeof(char) * longest_login), &stringcomp);

    same = 0;

    /* Check for multiple copies of the same UID */
    for (i = 0; i < (passwd_lines - 1); i++) {
	if (uid[i] < config.minuid || uid[i] > config.maxuid)
	    fprintf(my_stdout, "UID %d might be unattended\n", uid[i]);
	if (uid[i] == uid[i + 1])
	    same++;
	else {
	    if (same > 0)
		fprintf(my_stdout, "passwd file had %d copies of UID %d\n", same + 1, uid[i]);
	    same = 0;
	}
    }

    same = 0;

    /* Check for multiple copies of the same GID */
    for (i = 0; i < (passwd_lines - 1); i++) {
	if (gid[i] < config.mingid || gid[i] > config.maxgid)
	    fprintf(my_stdout, "GID %d might be unattended\n", gid[i]);
	if (gid[i] == gid[i + 1])
	    same++;
	else {
	    if (same > 0)
		fprintf(my_stdout, "passwd file had %d copies of GID %d\n", same + 1, gid[i]);
	    same = 0;
	}
    }

    same = 0;

    /* Check for multiple copies of the same login */
    for (i = 0; i < (passwd_lines - 1); i++) {
	if (!(strcmp(&login[i * longest_login], &login[(i + 1) * longest_login])))
	    same++;
	else {
	    if (same > 0)
		fprintf(my_stdout, "passwd file had %d copies of login \"%s\"\n", same + 1, &login[i * longest_login]);
	    same = 0;
	}
    }

    /* UIDs are useless now */
    free(uid);

    /* Check group file */
    if (grp_file != NULL)
	chkgroup(grp_file, login, gid, 1);

    /* Check shadow group file */
    if (shadowgrp != NULL)
	chkgroup(shadowgrp, login, NULL, 0);

    /* No more need for these pointers, too */
    free(gid);

    /* Check shadow file */
    if (shadow_file != NULL)
	chkshadow(shadow_file, login);

    /* Rest of the housework */
    free(login);
}

/* Check group and shadow group files */
void chkgroup(FILE *group_file, char *logins, int *passwd_gids, int g_or_s)
{
    int c, col = 0, grplines = 0, grpnamelen = 0, thisname = 0, *grpgid = NULL;
    char *grpnames, grp_line[MAX_LINE_LEN], tmpchar = 0;

    /* g_or_s means are we examing group or shadow group file */
    if (g_or_s)
	fprintf(my_stdout, "\
**************\n\
* Group file *\n\
**************\n");
    else
	fprintf(my_stdout, "\
*********************\n\
* Shadow group file *\n\
*********************\n");

    /* Find out the number of lines in the group file
     * and do the checking */

    c = fgetc(group_file);

    while (!feof(group_file)) {

	/* Group name */
	if (col == 0 && c != ':')
	    if (c > 96 && c < 123);
	    else if (c > 47 && c < 58);
	    else if (c > 64 && c < 91);
	    else
		fprintf(my_stdout, "Alert! Group name in line %d has an illegal character \"%c\"\n", grplines + 1, c);

	/* Shadow group passwd */
	if (col == 1 && g_or_s == 0 && c == ':') {
	    if (thisname < 1)
		fprintf(my_stdout, "Line %d in shadow group does not have a password\n", grplines + 1);
	    else if (thisname != 13)
		fprintf(my_stdout, "Line %d in shadow group is locked\n", grplines + 1);
	}
	/* GID */ if (col == 2 && c != ':' && g_or_s)
	    if (c < 48 || c > 57)
		fprintf(my_stdout, "Alert! GID in line %d has an illegal character \"%c\"\n", grplines + 1, c);

	/* Colons */
	if (c == '\n') {
	    grplines++;
	    if (col != 3)
		fprintf(my_stdout, "Alert! Wrong number of colons %d in line %d\n", col, grplines);
	    col = 0;
	    thisname = 0;
	}
	/* How long is longest group name */
	if (c == ':') {
	    if (thisname > config.grouplenght && col == 0)
		fprintf(my_stdout, "In line %d there is a %d characters long group name\n", grplines, thisname);
	    if (thisname > grpnamelen && col == 0)
		grpnamelen = thisname;
	    col++;
	    thisname = 0;
	} else
	    thisname++;

	/* Seek for secuental commas */
	if ((col == 2 || col == 3) && c == ',') {
	    if (tmpchar == ',')
		previous_line++;
	    else
		previous_line = 0;
	    tmpchar = c;
	}
	/* Report secuental commas */
	if (previous_line > 0 && c != ',') {
	    fprintf(my_stdout, "Sequential commas \"%d\" in line %d\n", previous_line + 1, grplines + 1);
	    previous_line = 0;
	}
	/* Remember previous char (variable "previous_line" disturbs author) */
	if (c != ',') {
	    tmpchar = c;
	    previous_line = 0;
	}
	c = fgetc(group_file);
    }

    /* Rewind the group file */
    rewind(group_file);

    /* Allocate some space for gids and group names */
    if (g_or_s)
	grpgid = (int *) malloc((grplines + 1) * sizeof(int));
    grpnames = (char *) malloc((grpnamelen + 1) * grplines * sizeof(char));

    if (g_or_s)
	if (grpgid == NULL) {
	    printf("Memory allocation failure\n");
	    exit(1);
	}
    if (grpnames == NULL) {
	printf("Memory allocation failure\n");
	exit(1);
    }
    c = thisname = 0;

    /* Read gids and group names */
    while (!feof(group_file) && c < grplines) {
	fgets(grp_line, MAX_LINE_LEN, group_file);
	if (g_or_s)
	    grpgid[c] = field_n_to_int(grp_line, 3);
	sscanf(grp_line, "%[^::]s", &grpnames[c * grpnamelen]);
	/* If group line is longer than MAX_LINE_LEN, go to the next line */
	if (strlen(grp_line) > MAX_LINE_LEN - 2) {
	    fscanf(group_file, "%*[^\n]");
	    fgetc(group_file);
	}
	c++;
    }

    /* Sort the gids and group names */
    if (g_or_s)
	qsort(grpgid, grplines - 1, sizeof(int), &intcomp);
    qsort(grpnames, grplines - 1, (sizeof(char) * grpnamelen), &stringcomp);

    /* Check for multiple copies of GIDs */
    if (g_or_s) {
	for (c = 0; c < (grplines); c++) {
	    if (grpgid[c] == grpgid[c + 1])
		thisname++;
	    else {
		if (thisname > 0)
		    fprintf(my_stdout, "group file had %d copies of GID %d\n", thisname + 1, grpgid[c]);
		thisname = 0;
	    }
	}
    }
    thisname = 0;

    /* Check for multiple copies of the group names */
    for (c = 0; c < grplines; c++) {
	if (!(strcmp(&grpnames[c * grpnamelen], &grpnames[(c + 1) * grpnamelen])))
	    thisname++;
	else {
	    if (thisname > 0)
		fprintf(my_stdout, "group file had %d copies of group name \"%s\"\n", thisname + 1, &grpnames[c * grpnamelen]);
	    thisname = 0;
	}
    }

    /* Check the GIDs that are used in the password file */
    if (g_or_s) {
	c = col = 0;
	previous_line = (int) (log(grplines) / M_LN2) + 1;

	for (; c < (passwd_lines - 1); c++) {
	    int small = 0, between = (grplines / 2), big = grplines;
	    while (1) {
		if (passwd_gids[c] == grpgid[between])
		    break;
		else if (passwd_gids[c] < grpgid[between]) {
		    big = between;
		    between = (small + between) / 2;
		} else if (passwd_gids[c] > grpgid[between]) {
		    small = between;
		    between = (big + between) / 2;
		}
		if (col == previous_line) {
		    fprintf(my_stdout, "GID %d from the passwd file could not be located from the group file\n", passwd_gids[c]);
		    break;
		}
		col++;
	    }
	    col = 0;
	}
    }
    /* Read group members and check that they are also in the passwd file */
    rewind(group_file);
    previous_line = col = 0;
    c = (int) (log(passwd_lines) / M_LN2) + 1;

    while (!feof(group_file)) {
	int small, between, big;

	/* Group file must end in a lone line feed */
	previous_line = getgrpmember(g_or_s, grp_line, group_file, previous_line);
	if (feof(group_file) && strlen(grp_line)) {
	    grp_line[strlen(grp_line) - 1] = '\0';
	    fprintf(my_stdout, "group file does not end in a linefeed\n");
	}
	if (strlen(grp_line)) {
	    col = small = 0, between = (passwd_lines / 2), big = passwd_lines;
	    while (1) {
		if (!strcmp(grp_line, &logins[longest_login * between])) {
		    break;
		} else if (0 > strcmp(grp_line, &logins[longest_login * between])) {
		    big = between;
		    between = (small + between) / 2;
		} else if (0 < strcmp(grp_line, &logins[longest_login * between])) {
		    small = between;
		    between = (big + between) / 2;
		}
		if (col == c) {
		    fprintf(my_stdout, "I could not find group member \"%s\" from the passwd file\n", grp_line);
		    break;
		}
		col++;
	    }
	}
	col = 0;
    }

    /* Housework */
    if (g_or_s)
	free(grpgid);
    free(grpnames);
}

/* Check the shadow file */
void chkshadow(FILE *shadow_file, char *logins)
{
    int c, shadowlines = 0, shadownamelen = 0, this = 0;
    char *shadow_logins, shadow_line[MAX_LINE_LEN + 1];

    fprintf(my_stdout, "\
***************\n\
* Shadow file *\n\
***************\n");

    /* Find out the number of lines in the shadow file
     * and do the checking */

    /* Count lines */
    while (!feof(shadow_file)) {
	fgets(shadow_line, MAX_LINE_LEN, shadow_file);
	/* Go line checking subroutine */
	c = chkshadowline(shadow_line, shadowlines + 1);
	if (shadownamelen < c)
	    shadownamelen = c;
	/* Shadow file should end to two newlines (...\n\nEOF) */
	if (strlen(shadow_line) != 0 && feof(shadow_file))
	    fprintf(my_stdout, "passwd file does not end in a linefeed\n");
	shadowlines++;
	shadow_line[0] = '\0';
    }

    /* Add space for null */
    shadownamelen++;

    /* Allocate some space for shadow logins */
    shadow_logins = (char *) malloc(shadownamelen * (shadowlines + 1) * sizeof(char));

    if (shadow_logins == NULL) {
	printf("Memory allocation failure\n");
	exit(1);
    }
    /* Read shadow logins */
    rewind(shadow_file);
    c = 0;
    while (!feof(shadow_file)) {
	fgets(shadow_line, MAX_LINE_LEN, shadow_file);
	if (feof(shadow_file) && shadow_line[strlen(shadow_line) - 1] != '\n')
	    fprintf(my_stdout, "shadow file does not end in a linefeed\n");
	sscanf(shadow_line, "%[^:]s", &shadow_logins[c * shadownamelen]);
	c++;
    }

    /* Sort the shadow logins */
    qsort(shadow_logins, shadowlines - 1, (sizeof(char) * shadownamelen), &stringcomp);

    /* Check for multiple copies of the shadow logins */
    for (c = 0, this = 0; c < shadowlines - 1; c++) {
	if (!(strcmp(&shadow_logins[c * shadownamelen], &shadow_logins[(c + 1) * shadownamelen])))
	    this++;
	else {
	    if (this > 0)
		fprintf(my_stdout, "shadow file had %d copies of an entry \"%s\"\n", this + 1, &shadow_logins[c * shadownamelen]);
	    this = 0;
	}
    }

    /* Compare shadow logins and passwd logins. Every one should be in both
     * but neither of them should have any extra logins. */
    previous_line = (int) (log(shadowlines) / M_LN2) + 1;
    c = 0;
    while (c < shadowlines) {
	int getout = 0, small = 0, between = (passwd_lines / 2);
	int big = passwd_lines;

	while (1) {
	    if (!strcmp(&shadow_logins[c * shadownamelen], &logins[longest_login * between])) {
		/* Here we break up logins see code a bit bellow this */
		logins[longest_login * between] = '\0';
		break;
	    } else if (0 > strcmp(&shadow_logins[c * shadownamelen], &logins[longest_login * between])) {
		big = between;
		between = (small + between) / 2;
	    } else if (0 < strcmp(&shadow_logins[c * shadownamelen], &logins[longest_login * between])) {
		small = between;
		between = (big + between) / 2;
	    }
	    if (getout == previous_line) {
		fprintf(my_stdout, "Shadow entry \"%s\" could not be located from the passwd file\n", &shadow_logins[c * shadownamelen]);
		break;
	    }
	    getout++;
	}
	c++;
    }

    for (c = 0; c < passwd_lines - 1; c++)
	/* This is why we break up the logins we don't need to seek
	 * twice same stuff */
	if (strlen(&logins[longest_login * c]))
	    fprintf(my_stdout, "Alert! Passwd contains login \"%s\" which does not have a shadow entry\n", &logins[longest_login * c]);
}

/* Print version */
void version(void)
{
    fprintf(my_stdout, "%s version %.2f\n", programname, version_number);
}

/* Print help */
void usage(void)
{
    fprintf(my_stdout, "Usage: %s [OPTIONS]\n", programname);
    fprintf(my_stdout, "\
This is a passwd, group, shadow and gshadow file integrity checker.\n\
\n\
  -d --default          check files in /etc/\n\
  -p --passwd   path    path to the passwd file\n\
  -g --group    path    path to the group file\n\
  -s --shadow   path    path to the shadow file\n\
  -G --gshadow  path    path to the shadow group file\n\
  -f --file     file    output into a file\n\
  -v --version          output version information and exit\n\
  -h --help             output this screen\n\
\n\
Please report bugs to kerolasa@iki.fi\n\
\n");
}

/*******
 * EOF *
 *******/
