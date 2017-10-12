// Package all imports all the commands
package all

import (
	// Active commands
	_ "github.com/ncw/rclone/cmd"
	_ "github.com/ncw/rclone/cmd/authorize"
	_ "github.com/ncw/rclone/cmd/cat"
	_ "github.com/ncw/rclone/cmd/check"
	_ "github.com/ncw/rclone/cmd/cleanup"
	_ "github.com/ncw/rclone/cmd/cmount"
	_ "github.com/ncw/rclone/cmd/config"
	_ "github.com/ncw/rclone/cmd/copy"
	_ "github.com/ncw/rclone/cmd/copyto"
	_ "github.com/ncw/rclone/cmd/cryptcheck"
	_ "github.com/ncw/rclone/cmd/cryptdecode"
	_ "github.com/ncw/rclone/cmd/dbhashsum"
	_ "github.com/ncw/rclone/cmd/dedupe"
	_ "github.com/ncw/rclone/cmd/delete"
	_ "github.com/ncw/rclone/cmd/genautocomplete"
	_ "github.com/ncw/rclone/cmd/gendocs"
	_ "github.com/ncw/rclone/cmd/info"
        _ "github.com/ncw/rclone/cmd/listremotes"
	_ "github.com/ncw/rclone/cmd/ls"
	_ "github.com/ncw/rclone/cmd/ls2"
	_ "github.com/ncw/rclone/cmd/lsd"
	_ "github.com/ncw/rclone/cmd/lsjson"
	_ "github.com/ncw/rclone/cmd/lsl"
	_ "github.com/ncw/rclone/cmd/md5sum"
	_ "github.com/ncw/rclone/cmd/memtest"
	_ "github.com/ncw/rclone/cmd/mkdir"
	_ "github.com/ncw/rclone/cmd/mount"
	_ "github.com/ncw/rclone/cmd/move"
	_ "github.com/ncw/rclone/cmd/moveto"
	_ "github.com/ncw/rclone/cmd/ncdu"
	_ "github.com/ncw/rclone/cmd/obscure"
	_ "github.com/ncw/rclone/cmd/purge"
	_ "github.com/ncw/rclone/cmd/rcat"
	_ "github.com/ncw/rclone/cmd/rmdir"
	_ "github.com/ncw/rclone/cmd/rmdirs"
	_ "github.com/ncw/rclone/cmd/sha1sum"
	_ "github.com/ncw/rclone/cmd/size"
	_ "github.com/ncw/rclone/cmd/sync"
	_ "github.com/ncw/rclone/cmd/tree"
	_ "github.com/ncw/rclone/cmd/version"
)
