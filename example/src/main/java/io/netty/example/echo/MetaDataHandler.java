package io.netty.example.echo;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

/**
 * @author yhhu
 * @date 2021/2/8
 * @description
 */
public class MetaDataHandler extends SimpleChannelInboundHandler<String> {
    private String metaData;

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        metaData = msg;
        ctx.fireChannelRead(msg);
    }


    public static String getMetaData(Channel channel) {
        MetaDataHandler metaDataHandler = channel.pipeline().get(MetaDataHandler.class);
        return metaDataHandler.metaData;
    }


}
