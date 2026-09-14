# DSH official npm package, pinned version —— 与飞牛实例(0.1.5-rc.1)保持一致
# 配方继承自 /opt/dsh/Dockerfile（旧实例，生产验证过）
FROM node:24-slim

ARG DSH_VERSION=0.1.5-rc.1

# git/procps/python3/make/g++：DSH 常调外部命令；openssh-client：dsh-ssh 插件备用
RUN apt-get update \
    && apt-get install -y --no-install-recommends git procps python3 make g++ openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g "@deepseek-ai/dsh@${DSH_VERSION}" \
    && corepack enable \
    && corepack prepare pnpm@11.7.0 --activate \
    && npm cache clean --force \
    && command -v dsh

# npm 11.19+ 默认不执行第三方安装脚本（本包安装时共 5 个被跳过）。
# 其中唯一有实际作用的一步在这里补跑：恢复 node-pty 预编译 spawn-helper 的可执行位。
# 缺了它，DSH 的终端 / 子进程(subprocess-local) 功能会异常。
RUN node /usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-subprocess-local/scripts/ensure-spawn-helper.mjs \
    && find /usr/local/lib/node_modules -name spawn-helper -printf 'BUILD-CHECK %M %p\n'

# 运行时工具补全：CA 根证书 + 技能脚本依赖。
# 缺 ca-certificates 时 git/curl 走 HTTPS 会报 "server certificate verification
# failed (CAfile: none)"，github 技能(git clone / gh-api)与 git 协议插件都会失败。
# 单独成层是为了不动上面昂贵的 npm 层（重建只需几秒而非重下 1.2GB）。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq rsync zip unzip \
    && rm -rf /var/lib/apt/lists/*

# 关键：官方 node 镜像自带 ENTRYPOINT [docker-entrypoint.sh]，会把未知命令当前置成 node。
# 显式声明 ENTRYPOINT 后，compose 的 command: ["web", ...] 才会被当成 dsh 的子命令。
ENTRYPOINT ["dsh"]

# node 用户(uid 1000)随基础镜像提供，与宿主挂载目录属主对齐
USER node
WORKDIR /home/node

# 本实例用 3082，避开旧实例的 3080
EXPOSE 3082
CMD ["dsh", "web", "--no-open"]
