import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class JwtAuth {
  @PrimaryGeneratedColumn()
  Id: number;

  @Column({ nullable: false })
  Sub: number;

  @Column({ nullable: false })
  Access: string;

  @Column({ nullable: false })
  Refresh: string;
}
