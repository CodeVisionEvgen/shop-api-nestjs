import { ConfigService } from '@nestjs/config';
import { ImageKitModuleOptions } from 'imagekit-nestjs';

export const ImageKitConfig = (
  configService: ConfigService,
): ImageKitModuleOptions => ({
  privateKey: configService.get('IMAGEKIT_PRIVATE_KEY'),
  publicKey: configService.get('IMAGEKIT_PUBLIC_KEY'),
  urlEndpoint: configService.get('IMAGEKIT_URL_ENDPOINT'),
});
