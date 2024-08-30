import { Module } from '@nestjs/common';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';
import { AccessTokenStrategy } from '../../strategies/accessToken.strategy';
import { UserModule } from '../../src/user/user.module';

@Module({
  controllers: [ProductController],
  providers: [ProductService, AccessTokenStrategy],
  imports: [UserModule],
})
export class ProductModule {}
