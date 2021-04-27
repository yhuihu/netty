package io.netty.example.echo;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageCodec;
import io.netty.util.CharsetUtil;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.List;

/**
 * @author yhhu
 * @date 2021/2/26
 * @description 自定义半包案例
 */
public class CommonCoder extends ByteToMessageCodec<Object> {
    private final int frameLength = 8;
    @Override
    protected void encode(ChannelHandlerContext ctx, Object bytes, ByteBuf byteBuf) throws Exception {
        byte[] bytes1 = bytes.toString().getBytes();
        int length = bytes1.length;
        String trueByte = addLengthSize(length) + bytes;
        byteBuf.writeBytes(trueByte.getBytes());
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        Object decoded = decode(ctx, in);
        if (decoded != null) {
            out.add(decoded);
        }
    }

    protected Object decode(
            @SuppressWarnings("UnusedParameters") ChannelHandlerContext ctx, ByteBuf in) throws Exception {
        in.readableBytes();
        if (in.readableBytes() <= frameLength) {
            return null;
        } else {
            in.markReaderIndex();
            ByteBuf byteBuf = in.readRetainedSlice(frameLength);
            String lengthStr = byteBuf.toString(CharsetUtil.UTF_8);
            int trueLength = stringToInt(lengthStr);
            if (in.readableBytes() < trueLength) {
                in.resetReaderIndex();
                return null;
            }
            return in.readBytes(trueLength);
        }
    }

    private static int stringToInt(String length) {
        return Integer.parseInt(length.replaceAll("^(0+)", ""));
    }

    private static String addLengthSize(int lengthSize){
        NumberFormat numberFormat = new DecimalFormat("00000000");
        return numberFormat.format(lengthSize);
    }
}
