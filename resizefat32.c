#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

struct fat32_bpb {
	uint8_t  jmp_boot[3];
	uint8_t  oem_name[8];
	uint16_t bytes_per_sector;
	uint8_t  sectors_per_cluster;
	uint16_t reserved_sectors_cnt;
	uint8_t  num_fats;
	uint16_t root_entry_cnt;
	uint16_t total_sectors_16;
	uint8_t  media;
	uint16_t fat_size_16;
	uint16_t sectors_per_track;
	uint16_t num_heads;
	uint32_t hidden_sectors;
	uint32_t total_sectors_32;
	uint32_t fat_size_32;
	uint16_t ext_flags;
	uint16_t fs_ver;
	uint32_t root_cluster;
	uint16_t fs_info;
	uint16_t backup_boot_sector;
	uint8_t  reserved[12];
	uint8_t  drive_num;
	uint8_t  reserved_nt;
	uint8_t  boot_sig;
	uint32_t volume_id;
	uint8_t  volume_label[11];
	uint8_t  fs_type[8];
} __attribute__((packed));

struct fat32_fsinfo {
	uint32_t lead_sig;
	char reserved1[0x1e0];
	uint32_t struct_sig;
	uint32_t free_count;
	uint32_t next_free;
	char reserved2[0x00c];
	uint32_t trail_sig;
} __attribute__((packed));

struct fat32 {
	struct fat32_bpb *bpb;
	struct fat32_bpb *backup_bpb;
	struct fat32_fsinfo *fsinfo;
	uint32_t *fat;
	uint8_t *data;
};

int is_pow2(uint32_t x)
{
	return (x != 0) && ((x & (x - 1)) == 0);
}

int validate_fat32_bpb(struct fat32_bpb *bpb)
{
	if (bpb->fat_size_16 || bpb->total_sectors_16 || bpb->root_entry_cnt) {
		fprintf(stderr, "ERROR: not a valid FAT32 volume, might be FAT12/FAT16\n");
		errno = EINVAL;
		return -1;
	}

	if (!is_pow2(bpb->bytes_per_sector)) {
		fprintf(stderr, "ERROR: invalid sector size\n");
		errno = EINVAL;
		return -1;
	}

	if (!is_pow2(bpb->sectors_per_cluster)) {
		fprintf(stderr, "ERROR: invalid cluster size\n");
		errno = EINVAL;
		return -1;
	}

	if (!bpb->num_fats) {
		fprintf(stderr, "ERROR: invalid number of FATs\n");
		errno = EINVAL;
		return -1;
	}

	if (!bpb->reserved_sectors_cnt) {
		fprintf(stderr, "ERROR: invalid number of reserved sectors\n");
		errno = EINVAL;
		return -1;
	}

	if (!bpb->total_sectors_32) {
		fprintf(stderr, "ERROR: invalid number of sectors\n");
		errno = EINVAL;
		return -1;
	}

	if (!bpb->fat_size_32) {
		fprintf(stderr, "ERROR: invalid FAT size\n");
		errno = EINVAL;
		return -1;
	}

	if (bpb->root_cluster < 2) {
		fprintf(stderr, "ERROR: invalid root cluster id\n");
		errno = EINVAL;
		return -1;
	}

	if (bpb->fs_info >= bpb->reserved_sectors_cnt) {
		fprintf(stderr, "ERROR: FSInfo sector points outside of the reserved area\n");
		errno = EINVAL;
		return -1;
	}

	if (bpb->backup_boot_sector >= bpb->reserved_sectors_cnt) {
		fprintf(stderr, "ERROR: backup BPB sector points outside of the reserved area\n");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int validate_fat32_fsinfo(struct fat32_fsinfo *fsinfo)
{
	if (fsinfo->lead_sig != 0x41615252 || fsinfo->struct_sig != 0x61417272 || fsinfo->trail_sig != 0xAA550000) {
		fprintf(stderr, "ERROR: invalid fsinfo signature detected\n");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int load_fat32(struct fat32 *fat32, uint8_t *buf, size_t size)
{
	struct fat32_bpb *bpb = NULL;
	struct fat32_bpb *backup_bpb = NULL;
	struct fat32_fsinfo *fsinfo = NULL;
	uint32_t *fat = NULL;
	uint8_t *data = NULL;

	if (size < 0x200) {
		fprintf(stderr, "ERROR: volume too small to contain valid FAT32 signature\n");
		errno = ERANGE;
		return -1;
	}

	if (buf[0x1fe] != 0x55 || buf[0x1ff] != 0xaa) {
		fprintf(stderr, "ERROR: Invalid boot signature\n");
		errno = EINVAL;
		return -1;
	}

	bpb = (struct fat32_bpb *) buf;
	if (validate_fat32_bpb(bpb) == -1) return -1;

	if (bpb->total_sectors_32 * bpb->bytes_per_sector > size) {
		fprintf(stderr, "ERROR: number of sectors beyond volume capacity\n");
		errno = ERANGE;
		return -1;
	}

	if (bpb->backup_boot_sector) {
		backup_bpb = (struct fat32_bpb *) (buf + (bpb->backup_boot_sector * bpb->bytes_per_sector));
		if (memcmp(bpb, backup_bpb, sizeof(struct fat32_bpb)) != 0) fprintf(stderr, "WARING: backup BPB not up to date\n");
	}

	if (bpb->fs_info) {
		fsinfo = (struct fat32_fsinfo *) (buf + (bpb->fs_info * bpb->bytes_per_sector));
		if (validate_fat32_fsinfo(fsinfo) ==  -1) {
			fprintf(stderr, "WARING: fsinfo invalid, this sector will be ignored\n");
			fsinfo = NULL;
		}
	}

	fat = (uint32_t *) (buf + (bpb->reserved_sectors_cnt * bpb->bytes_per_sector));
	data = (buf + ((bpb->reserved_sectors_cnt + (bpb->num_fats * bpb->fat_size_32)) * bpb->bytes_per_sector));

	fat32->bpb = bpb;
	fat32->backup_bpb = backup_bpb;
	fat32->fsinfo = fsinfo;
	fat32->fat = fat;
	fat32->data = data;

	return 0;
}

uint32_t round_up_div(uint32_t a, uint32_t b)
{
	return (a + b - 1) / b;
}

uint32_t get_num_clusters_target_size_fat32(struct fat32 *fat32, size_t size)
{
	uint32_t target_sectors;
	uint32_t cluster_limit;
	uint32_t fat_sectors;
	uint32_t data_sectors;
	uint32_t clusters;

	target_sectors = (size / fat32->bpb->bytes_per_sector) - fat32->bpb->reserved_sectors_cnt;
	cluster_limit = target_sectors / fat32->bpb->sectors_per_cluster;
	fat_sectors = round_up_div((cluster_limit + 2) * 4, fat32->bpb->bytes_per_sector);
	data_sectors = target_sectors - (fat_sectors * fat32->bpb->num_fats);
	clusters = data_sectors / fat32->bpb->sectors_per_cluster;

	return clusters;
}

uint32_t get_last_cluster_id_fat32(struct fat32 *fat32)
{
	uint32_t num_clusters = (fat32->bpb->fat_size_32 * fat32->bpb->bytes_per_sector) / 4;
	uint32_t last_cluster_id = 1;

	for (uint32_t i = 2; i < num_clusters; ++i) if (fat32->fat[i] && fat32->fat[i] != 0x0ffffff7) last_cluster_id = i;

	return last_cluster_id;
}

void sync_backup_fat32_bpb(struct fat32 *fat32)
{
	if (fat32->backup_bpb) memcpy(fat32->backup_bpb, fat32->bpb, sizeof(struct fat32_bpb));
}

void sync_fat32_fsinfo(struct fat32 *fat32, uint32_t clusters)
{
	uint32_t free_count = 0;
	uint32_t next_free = 0xffffffff;

	if (!fat32->fsinfo) return;

	for (uint32_t i = 2; i < clusters + 2; ++i) if (fat32->fat[i] == 0) {
		++free_count;
		if (next_free == 0xffffffff) next_free = i;
	}

	fat32->fsinfo->free_count = free_count;
	fat32->fsinfo->next_free = next_free;
}

int32_t resize_fat32(struct fat32 *fat32, uint32_t clusters)
{
	uint32_t min_clusters;
	uint32_t fat_sectors;
	uint32_t *fat;
	uint32_t copy_sectors;

	ssize_t data_shift;
	size_t data_size;

	min_clusters = get_last_cluster_id_fat32(fat32) - 1;
	if (clusters < min_clusters) clusters = min_clusters;
	if (clusters > INT32_MAX) {
		errno = ERANGE;
		return -1;
	}

	fat_sectors = round_up_div((clusters + 2) * 4, fat32->bpb->bytes_per_sector);
	fat = calloc(fat_sectors, fat32->bpb->bytes_per_sector);
	if (!fat) {
		perror("calloc");
		return -1;
	}

	copy_sectors = (fat_sectors < fat32->bpb->fat_size_32) ? fat_sectors : fat32->bpb->fat_size_32;
	memcpy(fat, fat32->fat, copy_sectors * fat32->bpb->bytes_per_sector);

	data_shift = ((ssize_t) fat_sectors - (ssize_t) fat32->bpb->fat_size_32) * fat32->bpb->num_fats * fat32->bpb->bytes_per_sector;
	data_size = min_clusters * fat32->bpb->sectors_per_cluster * fat32->bpb->bytes_per_sector;

	memmove(fat32->data + data_shift, fat32->data, data_size);
	fat32->data += data_shift;

	for (int i = 0; i < fat32->bpb->num_fats; ++i) memcpy(((uint8_t *) fat32->fat) + (i * fat_sectors * fat32->bpb->bytes_per_sector), fat, fat_sectors * fat32->bpb->bytes_per_sector);

	fat32->bpb->fat_size_32 = fat_sectors;
	fat32->bpb->total_sectors_32 = fat32->bpb->reserved_sectors_cnt + (fat32->bpb->num_fats * fat_sectors) + (clusters * fat32->bpb->sectors_per_cluster);

	sync_backup_fat32_bpb(fat32);
	sync_fat32_fsinfo(fat32, clusters);

	free(fat);
	return clusters;
}

ssize_t get_file_size(int fd)
{
	ssize_t current_pos;
	ssize_t size;

	current_pos = lseek(fd, 0, SEEK_CUR);
	if (current_pos == -1) {
		perror("lseek");
		return -1;
	}

	size = lseek(fd, 0, SEEK_END);
	if (size == -1) {
		perror("lseek");
		return -1;
	}

	if (lseek(fd, current_pos, SEEK_SET) == -1) {
		perror("lseek");
		return -1;
	}

	return size;
}

ssize_t parse_size_arg(char *arg)
{
	char *endptr;
	ssize_t size = strtol(arg, &endptr, 10);
	if (size < 0 || strlen(endptr) > 1) {
		errno = EINVAL;
		return -1;
	}

	switch (*endptr)
	{
	case 'G':
		size *= 1024;
		__attribute__ ((fallthrough));
	case 'M':
		size *= 1024;
		__attribute__ ((fallthrough));
	case 'K':
		size *= 1024;
	}

	return size;
}

void print_usage(char *name)
{
	fprintf(stderr,
		"usage: %s [-s min|max|SIZE] [-t] FILE\n\n"
		"  -s    New size for FAT32 volume.\n"
		"        Use 'max' to fill available disk space. (default)\n"
		"        Use 'min' to shrink file system to the smallest possible size.\n\n"
		"  -t    Truncate disk file size to match the file systems number of sectors.\n"
		"        This only works on disk image files, not on block devices\n\n", name);
	exit(1);
}

int main(int argc, char **argv)
{
	enum { MODE_MIN, MODE_MAX, MODE_TARGET } arg_mode = MODE_MAX;
	ssize_t arg_size = 0;
	int arg_truncate = 0;
	char *arg_file = NULL;

	int fd;
	ssize_t size;
	uint8_t *buf;

	struct fat32 fat32;

	uint32_t clusters;
	uint32_t original_sectors;
	size_t final_size;

	int ret = 0;

	for (int opt; (opt = getopt(argc, argv, "s:th")) != -1; ) {
		if (opt == 's') {
			if (strcmp(optarg, "min") == 0) arg_mode = MODE_MIN;
			else if (strcmp(optarg, "max") == 0) arg_mode = MODE_MAX;
			else {
				arg_mode = MODE_TARGET;
				arg_size = parse_size_arg(optarg);
				if (arg_size == -1) {
					fprintf(stderr, "ERROR: invalid size argument '%s'\n", optarg);
					exit(1);
				}
			}
		}
		else if (opt == 't') arg_truncate = 1;
		else print_usage(argv[0]);
	}

	if (optind != argc - 1) print_usage(argv[0]);
	arg_file = argv[optind];

	fd = open(arg_file, O_RDWR);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

	size = get_file_size(fd);
	if (size == -1) exit(1);

	if (arg_truncate && size < arg_size) {
		if (ftruncate(fd, arg_size) == -1) {
			perror("ftruncate");
			exit(1);
		}
		size = arg_size;
	}

	if (size < arg_size) {
		fprintf(stderr, "ERROR: requested size '%lu' exceeds disk capacity '%lu'. Provide -t if you want disk image files to automatically be resized.\n", arg_size, size);
		exit(1);
	}

	buf = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	if (load_fat32(&fat32, buf, size) == -1) exit(1);

	if (arg_mode == MODE_MIN) clusters = 0;
	else if (arg_mode == MODE_MAX) clusters = get_num_clusters_target_size_fat32(&fat32, size);
	else clusters = get_num_clusters_target_size_fat32(&fat32, arg_size);

	original_sectors = fat32.bpb->total_sectors_32;

	if (resize_fat32(&fat32, clusters) == -1) {
		fprintf(stderr, "ERROR: failed to resize volume\n");
		exit(1);
	}

	final_size = fat32.bpb->total_sectors_32 * fat32.bpb->bytes_per_sector;
	printf("resized FAT32 volume %u -> %u sectors (%.2f MiB -> %.2f MiB)\n",
		original_sectors,
		fat32.bpb->total_sectors_32,
		(original_sectors * fat32.bpb->bytes_per_sector) / (1024.0 * 1024.0),
		(fat32.bpb->total_sectors_32 * fat32.bpb->bytes_per_sector) / (1024.0 * 1024.0));

	if (arg_mode == MODE_TARGET && final_size != (size_t) arg_size) {
		if (final_size < (size_t) arg_size) final_size = arg_size;
		else {
			fprintf(stderr, "ERROR: volume too full to resize to requested target size, resized to minimum needed\n");
			ret = 1;
		}
	}

	if (munmap(buf, size) == -1) {
		perror("munmap");
		exit(1);
	}

	if (arg_truncate) {
		if (ftruncate(fd, final_size) == -1) {
			perror("ftruncate");
			exit(1);
		}
	}

	if (close(fd) == -1) {
		perror("close");
		exit(1);
	}

	return ret;
}
